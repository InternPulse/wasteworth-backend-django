# This file contains all payment endpoint implementations
# Copy this content to views.py

from rest_framework import status
from rest_framework.decorators import api_view, permission_classes
from rest_framework.permissions import IsAuthenticated
from rest_framework.response import Response
from django.views.decorators.csrf import csrf_exempt
from django.db import transaction as db_transaction
from django.shortcuts import get_object_or_404
from django.utils import timezone
from decimal import Decimal
import uuid
import json
import logging

from apps.marketplace.models import MarketplaceListing
from apps.listings.models import Listing
from .models import Payment
from .paystack_client import PaystackClient
from .utils import process_disposer_payout
from utils.rate_limiter import rate_limit, user_key

logger = logging.getLogger(__name__)


# ===================================================================
# PAYMENT INITIALIZATION
# ===================================================================

@api_view(['POST'])
@permission_classes([IsAuthenticated])
@rate_limit(key_func=user_key('payment_init'), rate=10, per=3600)
def initialize_payment(request):
    """
    Initialize a payment for a marketplace listing.

    POST /api/v1/payments/initialize/

    Request:
    {
        "listing_id": "uuid",
        "amount": "255.00"  (optional: for verification)
    }

    Response:
    {
        "success": true,
        "payment_id": "uuid",
        "authorization_url": "https://checkout.paystack.com/...",
        "access_code": "...",
        "reference": "WW-...",
        "amount": "255.00",
        "currency": "NGN"
    }
    """
    try:
        user = request.user
        listing_id = request.data.get('listing_id')
        amount = request.data.get('amount')

        # Validate listing_id
        if not listing_id:
            return Response({
                'success': False,
                'message': 'listing_id is required'
            }, status=status.HTTP_400_BAD_REQUEST)

        # Get listing
        listing = get_object_or_404(Listing, id=listing_id)

        # Ensure user is not the disposer
        if listing.user_id == user:
            return Response({
                'success': False,
                'message': 'You cannot purchase your own listing'
            }, status=status.HTTP_400_BAD_REQUEST)

        # Check if listing is available
        if listing.status not in ['pending', 'accepted']:
            return Response({
                'success': False,
                'message': f'Listing is not available for purchase (status: {listing.status})'
            }, status=status.HTTP_400_BAD_REQUEST)

        # Verify amount matches listing price
        expected_amount = listing.reward_estimate
        if amount:
            provided_amount = Decimal(str(amount))
            if provided_amount != expected_amount:
                return Response({
                    'success': False,
                    'message': f'Amount mismatch. Expected: {expected_amount}, Provided: {provided_amount}'
                }, status=status.HTTP_400_BAD_REQUEST)
        else:
            amount = expected_amount

        # Create or get marketplace listing
        marketplace_listing, created = MarketplaceListing.objects.get_or_create(
            listing_id=listing,
            defaults={
                'recycler_id': user,
                'price': amount,
                'escrow_status': 'pending'
            }
        )

        # If already exists, check for idempotency
        if not created:
            # If payment was already initiated by this user, return existing payment details
            if marketplace_listing.escrow_status == 'payment_initiated' and marketplace_listing.recycler_id == user:
                existing_payment = Payment.objects.filter(
                    marketplace_listing=marketplace_listing,
                    payer=user,
                    status='pending'
                ).first()

                if existing_payment:
                    return Response({
                        'success': True,
                        'message': 'Payment already initialized. Redirect user to authorization_url.',
                        'payment_id': str(existing_payment.payment_id),
                        'authorization_url': existing_payment.paystack_authorization_url,
                        'access_code': existing_payment.paystack_access_code,
                        'reference': existing_payment.paystack_reference,
                        'amount': str(existing_payment.amount),
                        'currency': 'NGN',
                        'note': 'This payment was already initiated. Use the existing checkout URL.'
                    }, status=status.HTTP_200_OK)

            # If listing is in any other non-retryable state
            if marketplace_listing.escrow_status not in ['pending', 'failed']:
                return Response({
                    'success': False,
                    'message': f'Listing already has an active transaction (status: {marketplace_listing.escrow_status})'
                }, status=status.HTTP_400_BAD_REQUEST)

            # For pending or failed, allow retry
            marketplace_listing.recycler_id = user
            marketplace_listing.save()

        # Generate unique reference
        reference = f"WW-{uuid.uuid4().hex[:12].upper()}"

        # Initialize Paystack payment
        paystack = PaystackClient()
        result = paystack.initialize_payment(
            email=user.email,
            amount=amount,
            reference=reference,
            metadata={
                'listing_id': str(listing.id),
                'marketplace_listing_id': str(marketplace_listing.id),
                'disposer_id': str(listing.user_id.id),
                'recycler_id': str(user.id),
                'quantity': float(listing.quantity),
                'waste_type': listing.waste_type
            }
        )

        if not result['success']:
            return Response({
                'success': False,
                'message': 'Failed to initialize payment with Paystack',
                'error': result.get('error')
            }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

        # Create payment record
        with db_transaction.atomic():
            payment = Payment.objects.create(
                marketplace_listing=marketplace_listing,
                payer=user,
                amount=amount,
                currency='NGN',
                paystack_reference=reference,
                paystack_access_code=result['access_code'],
                paystack_authorization_url=result['authorization_url'],
                status='pending',
                payment_provider='paystack'
            )

            # Update marketplace listing
            marketplace_listing.escrow_status = 'payment_initiated'
            marketplace_listing.payment_initiated_at = timezone.now()
            marketplace_listing.save()

        logger.info(f"Payment initialized: {payment.payment_id} for listing {listing.id} by user {user.email}")

        return Response({
            'success': True,
            'message': 'Payment initialized successfully. Redirect user to authorization_url.',
            'payment_id': str(payment.payment_id),
            'authorization_url': result['authorization_url'],
            'access_code': result['access_code'],
            'reference': reference,
            'amount': str(amount),
            'currency': 'NGN'
        }, status=status.HTTP_200_OK)

    except Listing.DoesNotExist:
        return Response({
            'success': False,
            'message': 'Listing not found'
        }, status=status.HTTP_404_NOT_FOUND)

    except Exception as e:
        logger.error(f"Error initializing payment for user {request.user.email}: {str(e)}")
        return Response({
            'success': False,
            'message': 'An error occurred while initializing payment',
            'error': str(e)
        }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)


# ===================================================================
# PAYMENT VERIFICATION
# ===================================================================

@api_view(['GET'])
@permission_classes([IsAuthenticated])
@rate_limit(key_func=user_key('payment_verify'), rate=20, per=3600)  # 20 verifications per hour per user
def verify_payment(request):
    """
    Verify a payment after Paystack redirects back.

    GET /api/v1/payments/verify/?reference=WW-xxxxx

    Response:
    {
        "success": true,
        "payment": {...},
        "marketplace_listing": {...}
    }
    """
    try:
        user = request.user
        reference = request.query_params.get('reference')

        if not reference:
            return Response({
                'success': False,
                'message': 'Payment reference is required'
            }, status=status.HTTP_400_BAD_REQUEST)

        # Get payment record
        try:
            payment = Payment.objects.get(paystack_reference=reference)
        except Payment.DoesNotExist:
            return Response({
                'success': False,
                'message': 'Payment not found'
            }, status=status.HTTP_404_NOT_FOUND)

        # Verify user owns this payment
        if payment.payer != user:
            return Response({
                'success': False,
                'message': 'Unauthorized to verify this payment'
            }, status=status.HTTP_403_FORBIDDEN)

        # If already verified, return success
        if payment.is_verified and payment.status == 'success':
            return Response({
                'success': True,
                'message': 'Payment already verified',
                'payment': {
                    'payment_id': str(payment.payment_id),
                    'status': payment.status,
                    'amount': str(payment.amount),
                    'reference': payment.paystack_reference,
                    'verified_at': payment.verified_at.isoformat() if payment.verified_at else None
                },
                'marketplace_listing': {
                    'id': str(payment.marketplace_listing.id),
                    'escrow_status': payment.marketplace_listing.escrow_status
                }
            }, status=status.HTTP_200_OK)

        # Verify with Paystack
        paystack = PaystackClient()
        result = paystack.verify_payment(reference)

        if not result['success']:
            payment.status = 'failed'
            payment.last_error = result.get('error', 'Verification failed')
            payment.save()

            return Response({
                'success': False,
                'message': 'Payment verification failed',
                'error': result.get('error')
            }, status=status.HTTP_400_BAD_REQUEST)

        # Verify amount matches
        if result['amount'] != payment.amount:
            logger.error(f"Amount mismatch for payment {payment.payment_id}: expected {payment.amount}, got {result['amount']}")
            payment.status = 'failed'
            payment.last_error = 'Amount mismatch'
            payment.save()

            return Response({
                'success': False,
                'message': 'Payment amount mismatch'
            }, status=status.HTTP_400_BAD_REQUEST)

        # Update payment and marketplace listing
        with db_transaction.atomic():
            payment.status = 'success'
            payment.is_verified = True
            payment.verified_at = timezone.now()
            payment.payment_method = result.get('channel', '')
            # Convert Decimal to string for JSON serialization
            paystack_response = result.copy()
            if 'amount' in paystack_response:
                paystack_response['amount'] = str(paystack_response['amount'])
            payment.paystack_response = paystack_response
            payment.save()

            marketplace_listing = payment.marketplace_listing
            marketplace_listing.escrow_status = 'locked'
            marketplace_listing.payment_locked_at = timezone.now()
            marketplace_listing.save()

            listing = marketplace_listing.listing_id
            listing.status = 'accepted'
            listing.collector_id = user
            listing.save()

        logger.info(f"Payment verified: {payment.payment_id} for user {user.email}")

        return Response({
            'success': True,
            'message': 'Payment verified successfully. Escrow locked. Contact the disposer to collect the item.',
            'payment': {
                'payment_id': str(payment.payment_id),
                'status': payment.status,
                'amount': str(payment.amount),
                'reference': payment.paystack_reference,
                'paid_at': result.get('paid_at'),
                'payment_method': result.get('channel')
            },
            'marketplace_listing': {
                'id': str(marketplace_listing.id),
                'escrow_status': marketplace_listing.escrow_status,
                'listing_id': str(listing.id),
                'disposer': {
                    'name': listing.user_id.name,
                    'phone': listing.phone or listing.user_id.phone,
                    'location': listing.pickup_location
                }
            }
        }, status=status.HTTP_200_OK)

    except Exception as e:
        logger.error(f"Error verifying payment for user {request.user.email}: {str(e)}")
        return Response({
            'success': False,
            'message': 'An error occurred while verifying payment',
            'error': str(e)
        }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)


# ===================================================================
# ITEM RELEASE CONFIRMATION (DISPOSER)
# ===================================================================

@api_view(['POST'])
@permission_classes([IsAuthenticated])
@rate_limit(key_func=user_key('confirm_release'), rate=50, per=3600)  # 50 confirmations per hour per user
def confirm_item_released(request):
    """
    Disposer confirms they have released the item to the recycler.

    POST /api/v1/payments/confirm-release/

    Request:
    {
        "marketplace_listing_id": "uuid"
    }
    """
    try:
        user = request.user
        marketplace_listing_id = request.data.get('marketplace_listing_id')

        if not marketplace_listing_id:
            return Response({
                'success': False,
                'message': 'marketplace_listing_id is required'
            }, status=status.HTTP_400_BAD_REQUEST)

        marketplace_listing = get_object_or_404(MarketplaceListing, id=marketplace_listing_id)

        # Verify user is the disposer
        if marketplace_listing.listing_id.user_id != user:
            return Response({
                'success': False,
                'message': 'Only the disposer can confirm item release'
            }, status=status.HTTP_403_FORBIDDEN)

        # Idempotency: If already released, return success
        if marketplace_listing.escrow_status == 'item_released' and marketplace_listing.disposer_confirmed:
            return Response({
                'success': True,
                'message': 'Item release already confirmed.',
                'marketplace_listing': {
                    'id': str(marketplace_listing.id),
                    'escrow_status': marketplace_listing.escrow_status,
                    'released_at': marketplace_listing.item_released_at.isoformat() if marketplace_listing.item_released_at else None
                }
            }, status=status.HTTP_200_OK)

        # Verify escrow is locked
        if marketplace_listing.escrow_status != 'locked':
            return Response({
                'success': False,
                'message': f'Cannot confirm release. Current status: {marketplace_listing.escrow_status}'
            }, status=status.HTTP_400_BAD_REQUEST)

        # Update status
        with db_transaction.atomic():
            marketplace_listing.escrow_status = 'item_released'
            marketplace_listing.item_released_at = timezone.now()
            marketplace_listing.disposer_confirmed = True
            marketplace_listing.save()

            marketplace_listing.listing_id.status = 'in-progress'
            marketplace_listing.listing_id.save()

        logger.info(f"Item release confirmed by disposer {user.email} for marketplace listing {marketplace_listing.id}")

        return Response({
            'success': True,
            'message': 'Item release confirmed. The recycler has been notified to confirm receipt.',
            'marketplace_listing': {
                'id': str(marketplace_listing.id),
                'escrow_status': marketplace_listing.escrow_status
            }
        }, status=status.HTTP_200_OK)

    except MarketplaceListing.DoesNotExist:
        return Response({
            'success': False,
            'message': 'Marketplace listing not found'
        }, status=status.HTTP_404_NOT_FOUND)

    except Exception as e:
        logger.error(f"Error confirming item release: {str(e)}")
        return Response({
            'success': False,
            'message': 'An error occurred',
            'error': str(e)
        }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)


# ===================================================================
# ITEM RECEIPT CONFIRMATION (RECYCLER) - TRIGGERS ESCROW RELEASE
# ===================================================================

@api_view(['POST'])
@permission_classes([IsAuthenticated])
@rate_limit(key_func=user_key('confirm_receipt'), rate=50, per=3600)  # 50 confirmations per hour per user
def confirm_item_received(request):
    """
    Recycler confirms they have received the item.
    This triggers escrow release and reward distribution.

    POST /api/v1/payments/confirm-receipt/

    Request:
    {
        "marketplace_listing_id": "uuid"
    }
    """
    try:
        user = request.user
        marketplace_listing_id = request.data.get('marketplace_listing_id')

        if not marketplace_listing_id:
            return Response({
                'success': False,
                'message': 'marketplace_listing_id is required'
            }, status=status.HTTP_400_BAD_REQUEST)

        marketplace_listing = get_object_or_404(MarketplaceListing, id=marketplace_listing_id)

        # Verify user is the recycler
        if marketplace_listing.recycler_id != user:
            return Response({
                'success': False,
                'message': 'Only the recycler can confirm item receipt'
            }, status=status.HTTP_403_FORBIDDEN)

        # Idempotency: If already confirmed/released, return success
        if marketplace_listing.escrow_status in ['confirmed', 'released'] and marketplace_listing.recycler_confirmed:
            return Response({
                'success': True,
                'message': 'Item receipt already confirmed! Escrow has been released.',
                'marketplace_listing': {
                    'id': str(marketplace_listing.id),
                    'escrow_status': marketplace_listing.escrow_status,
                    'released_at': marketplace_listing.released_at.isoformat() if marketplace_listing.released_at else None
                },
                'note': 'This transaction was already processed. Rewards and payouts have been distributed.'
            }, status=status.HTTP_200_OK)

        # Verify item was released
        if marketplace_listing.escrow_status != 'item_released':
            return Response({
                'success': False,
                'message': f'Cannot confirm receipt. Current status: {marketplace_listing.escrow_status}'
            }, status=status.HTTP_400_BAD_REQUEST)

        # Process everything in atomic transaction
        with db_transaction.atomic():
            # Update marketplace listing
            marketplace_listing.escrow_status = 'confirmed'
            marketplace_listing.confirmed_at = timezone.now()
            marketplace_listing.recycler_confirmed = True
            marketplace_listing.save()

            # Update listing status
            marketplace_listing.listing_id.status = 'completed'
            marketplace_listing.listing_id.save()

            # Process rewards
            from apps.wallet.utils import process_marketplace_rewards
            reward_results = process_marketplace_rewards(marketplace_listing)

            # Initiate payout
            payout_result = process_disposer_payout(marketplace_listing)

            # Update to released status
            marketplace_listing.escrow_status = 'released'
            marketplace_listing.released_at = timezone.now()
            marketplace_listing.save()

        logger.info(f"Item receipt confirmed by recycler {user.email} for marketplace listing {marketplace_listing.id}")

        return Response({
            'success': True,
            'message': 'Item receipt confirmed! Escrow released, rewards distributed, and payout initiated.',
            'marketplace_listing': {
                'id': str(marketplace_listing.id),
                'escrow_status': marketplace_listing.escrow_status,
                'released_at': marketplace_listing.released_at.isoformat() if marketplace_listing.released_at else None
            },
            'rewards': {
                'disposer_points': reward_results['disposer_reward'].points if reward_results.get('disposer_reward') else 0,
                'recycler_points': reward_results['recycler_reward'].points if reward_results.get('recycler_reward') else 0,
                'disposer_referrer_bonus': reward_results['disposer_referrer_reward'].points if reward_results.get('disposer_referrer_reward') else 0,
                'recycler_referrer_bonus': reward_results['recycler_referrer_reward'].points if reward_results.get('recycler_referrer_reward') else 0,
                'errors': reward_results.get('errors', [])
            },
            'payout': {
                'payout_id': str(payout_result['payout_id']) if payout_result.get('success') else None,
                'amount': str(payout_result.get('amount', 0)),
                'status': payout_result.get('status', 'failed'),
                'error': payout_result.get('error') if not payout_result.get('success') else None
            }
        }, status=status.HTTP_200_OK)

    except MarketplaceListing.DoesNotExist:
        return Response({
            'success': False,
            'message': 'Marketplace listing not found'
        }, status=status.HTTP_404_NOT_FOUND)

    except Exception as e:
        logger.error(f"Error confirming item receipt: {str(e)}")
        return Response({
            'success': False,
            'message': 'An error occurred',
            'error': str(e)
        }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)


# ===================================================================
# PAYSTACK WEBHOOK HANDLER
# ===================================================================

@csrf_exempt
@api_view(['POST'])
def paystack_webhook(request):
    """
    Handle Paystack webhook events.

    POST /api/v1/payments/webhook/

    Events handled:
    - charge.success: Payment completed
    - transfer.success: Payout completed
    - transfer.failed: Payout failed
    """
    try:
        raw_body = request.body
        signature = request.headers.get('X-Paystack-Signature', '')

        # Verify signature
        paystack = PaystackClient()
        if not paystack.verify_webhook_signature(raw_body, signature):
            logger.warning("Invalid webhook signature received")
            return Response({
                'success': False,
                'message': 'Invalid signature'
            }, status=status.HTTP_401_UNAUTHORIZED)

        # Parse event data
        event_data = json.loads(raw_body.decode('utf-8'))
        event_type = event_data.get('event')

        logger.info(f"Received Paystack webhook: {event_type}")

        # Route to appropriate handler
        if event_type == 'charge.success':
            return handle_charge_success(event_data)
        elif event_type == 'transfer.success':
            return handle_transfer_success(event_data)
        elif event_type == 'transfer.failed':
            return handle_transfer_failed(event_data)
        else:
            logger.info(f"Unhandled webhook event: {event_type}")
            return Response({
                'success': True,
                'message': 'Event acknowledged'
            }, status=status.HTTP_200_OK)

    except Exception as e:
        logger.error(f"Error processing Paystack webhook: {str(e)}")
        return Response({
            'success': False,
            'message': 'Webhook processing error'
        }, status=status.HTTP_200_OK)


def handle_charge_success(event_data):
    """Handle successful payment webhook"""
    try:
        data = event_data['data']
        reference = data['reference']

        try:
            payment = Payment.objects.get(paystack_reference=reference)
        except Payment.DoesNotExist:
            return Response({'success': True}, status=status.HTTP_200_OK)

        if payment.is_verified and payment.status == 'success':
            return Response({'success': True}, status=status.HTTP_200_OK)

        amount_paid = Decimal(data['amount']) / 100
        if amount_paid != payment.amount:
            payment.status = 'failed'
            payment.last_error = 'Amount mismatch'
            payment.save()
            return Response({'success': False}, status=status.HTTP_400_BAD_REQUEST)

        with db_transaction.atomic():
            payment.status = 'success'
            payment.is_verified = True
            payment.verified_at = timezone.now()
            payment.payment_method = data.get('channel', '')
            payment.paystack_response = data
            payment.webhook_received_at = timezone.now()
            payment.save()

            marketplace_listing = payment.marketplace_listing
            if marketplace_listing.escrow_status != 'locked':
                marketplace_listing.escrow_status = 'locked'
                marketplace_listing.payment_locked_at = timezone.now()
                marketplace_listing.save()

                listing = marketplace_listing.listing_id
                listing.status = 'accepted'
                listing.collector_id = payment.payer
                listing.save()

        logger.info(f"Webhook processed: Payment {payment.payment_id} marked as success")
        return Response({'success': True}, status=status.HTTP_200_OK)

    except Exception as e:
        logger.error(f"Error handling charge.success webhook: {str(e)}")
        return Response({'success': False}, status=status.HTTP_200_OK)


def handle_transfer_success(event_data):
    """Handle successful payout webhook"""
    # TODO: Implement when using real Paystack transfers
    return Response({'success': True}, status=status.HTTP_200_OK)


def handle_transfer_failed(event_data):
    """Handle failed payout webhook"""
    # TODO: Implement when using real Paystack transfers
    return Response({'success': True}, status=status.HTTP_200_OK)
