# 🚀 WasteWorth Escrow Payment Implementation Plan (Continued)

**Part 2 of Comprehensive Architecture Review**

---

## 📋 Phase 2 (Continued): Payment Endpoints

### Step 2.3: Paystack Webhook Handler

**File:** `apps/payments/views.py` (continued)

```python
from django.views.decorators.csrf import csrf_exempt
from django.utils.decorators import method_decorator
import json


@csrf_exempt
@api_view(['POST'])
def paystack_webhook(request):
    """
    Handle Paystack webhook events.

    POST /api/v1/payments/webhook/

    Events handled:
    - charge.success: Payment completed successfully
    - transfer.success: Payout completed successfully
    - transfer.failed: Payout failed
    """
    try:
        # Get raw body for signature verification
        raw_body = request.body

        # Get signature from headers
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
                'message': 'Event acknowledged but not handled'
            }, status=status.HTTP_200_OK)

    except Exception as e:
        logger.error(f"Error processing Paystack webhook: {str(e)}")
        # Return 200 to prevent Paystack from retrying
        return Response({
            'success': False,
            'message': 'Webhook processing error',
            'error': str(e)
        }, status=status.HTTP_200_OK)


def handle_charge_success(event_data):
    """
    Handle successful payment webhook.

    This is called by Paystack when a payment succeeds.
    It's a safety net in case the user doesn't complete the verify flow.
    """
    try:
        data = event_data['data']
        reference = data['reference']

        # Get payment record
        try:
            payment = Payment.objects.get(paystack_reference=reference)
        except Payment.DoesNotExist:
            logger.warning(f"Payment not found for reference: {reference}")
            return Response({
                'success': True,
                'message': 'Payment not found (may be external transaction)'
            }, status=status.HTTP_200_OK)

        # If already processed, skip
        if payment.is_verified and payment.status == 'success':
            logger.info(f"Payment {payment.payment_id} already processed")
            return Response({
                'success': True,
                'message': 'Payment already processed'
            }, status=status.HTTP_200_OK)

        # Verify amount
        amount_paid = Decimal(data['amount']) / 100  # Convert from kobo
        if amount_paid != payment.amount:
            logger.error(f"Amount mismatch for payment {payment.payment_id}: expected {payment.amount}, got {amount_paid}")
            payment.status = 'failed'
            payment.last_error = 'Amount mismatch'
            payment.save()
            return Response({
                'success': False,
                'message': 'Amount mismatch'
            }, status=status.HTTP_400_BAD_REQUEST)

        # Update payment record
        with transaction.atomic():
            payment.status = 'success'
            payment.is_verified = True
            payment.verified_at = timezone.now()
            payment.payment_method = data.get('channel', '')
            payment.paystack_response = data
            payment.webhook_received_at = timezone.now()
            payment.save()

            # Lock escrow if not already locked
            marketplace_listing = payment.marketplace_listing
            if marketplace_listing.escrow_status != 'locked':
                marketplace_listing.escrow_status = 'locked'
                marketplace_listing.payment_locked_at = timezone.now()
                marketplace_listing.save()

                # Update listing status
                listing = marketplace_listing.listing_id
                listing.status = 'accepted'
                listing.collector_id = payment.payer
                listing.save()

        # TODO: Send notification to disposer
        # notify_disposer_payment_received(payment.marketplace_listing)

        logger.info(f"Webhook processed: Payment {payment.payment_id} marked as success")

        return Response({
            'success': True,
            'message': 'Payment webhook processed successfully'
        }, status=status.HTTP_200_OK)

    except Exception as e:
        logger.error(f"Error handling charge.success webhook: {str(e)}")
        return Response({
            'success': False,
            'message': 'Error processing webhook',
            'error': str(e)
        }, status=status.HTTP_200_OK)


def handle_transfer_success(event_data):
    """Handle successful payout webhook."""
    try:
        data = event_data['data']
        transfer_code = data['transfer_code']

        # Get payout record
        try:
            from .models import Payout
            payout = Payout.objects.get(paystack_transfer_code=transfer_code)
        except Payout.DoesNotExist:
            logger.warning(f"Payout not found for transfer_code: {transfer_code}")
            return Response({
                'success': True,
                'message': 'Payout not found'
            }, status=status.HTTP_200_OK)

        # Update payout status
        with transaction.atomic():
            payout.status = 'success'
            payout.is_completed = True
            payout.completed_at = timezone.now()
            payout.paystack_response = data
            payout.save()

        logger.info(f"Webhook processed: Payout {payout.payout_id} marked as success")

        # TODO: Send notification to disposer
        # notify_disposer_payout_success(payout)

        return Response({
            'success': True,
            'message': 'Transfer webhook processed successfully'
        }, status=status.HTTP_200_OK)

    except Exception as e:
        logger.error(f"Error handling transfer.success webhook: {str(e)}")
        return Response({
            'success': False,
            'message': 'Error processing webhook',
            'error': str(e)
        }, status=status.HTTP_200_OK)


def handle_transfer_failed(event_data):
    """Handle failed payout webhook."""
    try:
        data = event_data['data']
        transfer_code = data['transfer_code']

        # Get payout record
        try:
            from .models import Payout
            payout = Payout.objects.get(paystack_transfer_code=transfer_code)
        except Payout.DoesNotExist:
            logger.warning(f"Payout not found for transfer_code: {transfer_code}")
            return Response({
                'success': True,
                'message': 'Payout not found'
            }, status=status.HTTP_200_OK)

        # Update payout status
        with transaction.atomic():
            payout.status = 'failed'
            payout.last_error = data.get('message', 'Transfer failed')
            payout.paystack_response = data
            payout.save()

        logger.error(f"Webhook processed: Payout {payout.payout_id} marked as failed")

        # TODO: Send notification to admin for manual intervention
        # notify_admin_payout_failed(payout)

        return Response({
            'success': True,
            'message': 'Transfer failure webhook processed'
        }, status=status.HTTP_200_OK)

    except Exception as e:
        logger.error(f"Error handling transfer.failed webhook: {str(e)}")
        return Response({
            'success': False,
            'message': 'Error processing webhook',
            'error': str(e)
        }, status=status.HTTP_200_OK)
```

### Step 2.4: Confirm Item Release/Receipt Endpoints

**File:** `apps/payments/views.py` (continued)

```python
@api_view(['POST'])
@permission_classes([IsAuthenticated])
def confirm_item_released(request):
    """
    Disposer confirms they have released the item to the recycler.

    POST /api/v1/payments/confirm-release/

    Request:
    {
        "marketplace_listing_id": "uuid"
    }

    Response:
    {
        "success": true,
        "message": "Item release confirmed. Waiting for recycler confirmation.",
        "marketplace_listing": {
            "id": "uuid",
            "escrow_status": "item_released"
        }
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

        # Get marketplace listing
        marketplace_listing = get_object_or_404(MarketplaceListing, id=marketplace_listing_id)

        # Verify user is the disposer
        if marketplace_listing.listing_id.user_id != user:
            return Response({
                'success': False,
                'message': 'Only the disposer can confirm item release'
            }, status=status.HTTP_403_FORBIDDEN)

        # Verify escrow is locked
        if marketplace_listing.escrow_status != 'locked':
            return Response({
                'success': False,
                'message': f'Cannot confirm release. Current status: {marketplace_listing.escrow_status}'
            }, status=status.HTTP_400_BAD_REQUEST)

        # Update status
        with transaction.atomic():
            marketplace_listing.escrow_status = 'item_released'
            marketplace_listing.item_released_at = timezone.now()
            marketplace_listing.disposer_confirmed = True
            # Set auto-confirm deadline (7 days)
            marketplace_listing.auto_confirm_deadline = timezone.now() + timezone.timedelta(days=7)
            marketplace_listing.save()

            # Update listing status
            marketplace_listing.listing_id.status = 'in-progress'
            marketplace_listing.listing_id.save()

        logger.info(f"Item release confirmed by disposer {user.email} for marketplace listing {marketplace_listing.id}")

        # TODO: Send notification to recycler
        # notify_recycler_item_released(marketplace_listing)

        return Response({
            'success': True,
            'message': 'Item release confirmed. The recycler has been notified to confirm receipt.',
            'marketplace_listing': {
                'id': str(marketplace_listing.id),
                'escrow_status': marketplace_listing.escrow_status,
                'auto_confirm_deadline': marketplace_listing.auto_confirm_deadline.isoformat() if marketplace_listing.auto_confirm_deadline else None
            }
        }, status=status.HTTP_200_OK)

    except MarketplaceListing.DoesNotExist:
        return Response({
            'success': False,
            'message': 'Marketplace listing not found'
        }, status=status.HTTP_404_NOT_FOUND)

    except Exception as e:
        logger.error(f"Error confirming item release for user {request.user.email}: {str(e)}")
        return Response({
            'success': False,
            'message': 'An error occurred while confirming item release',
            'error': str(e)
        }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)


@api_view(['POST'])
@permission_classes([IsAuthenticated])
def confirm_item_received(request):
    """
    Recycler confirms they have received the item.
    This triggers escrow release and reward distribution.

    POST /api/v1/payments/confirm-receipt/

    Request:
    {
        "marketplace_listing_id": "uuid"
    }

    Response:
    {
        "success": true,
        "message": "Item receipt confirmed. Escrow released and rewards distributed.",
        "marketplace_listing": {
            "id": "uuid",
            "escrow_status": "released"
        },
        "rewards": {
            "disposer_points": 255,
            "recycler_points": 255,
            "referral_bonuses": []
        },
        "payout": {
            "payout_id": "uuid",
            "amount": "242.25",
            "status": "processing"
        }
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

        # Get marketplace listing
        marketplace_listing = get_object_or_404(MarketplaceListing, id=marketplace_listing_id)

        # Verify user is the recycler
        if marketplace_listing.recycler_id != user:
            return Response({
                'success': False,
                'message': 'Only the recycler can confirm item receipt'
            }, status=status.HTTP_403_FORBIDDEN)

        # Verify item was released
        if marketplace_listing.escrow_status != 'item_released':
            return Response({
                'success': False,
                'message': f'Cannot confirm receipt. Current status: {marketplace_listing.escrow_status}'
            }, status=status.HTTP_400_BAD_REQUEST)

        # Process everything in a transaction
        with transaction.atomic():
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

            # Initiate payout to disposer
            from .utils import process_disposer_payout
            payout_result = process_disposer_payout(marketplace_listing)

            # Update to released status
            marketplace_listing.escrow_status = 'released'
            marketplace_listing.released_at = timezone.now()
            marketplace_listing.save()

        logger.info(f"Item receipt confirmed by recycler {user.email} for marketplace listing {marketplace_listing.id}")

        # TODO: Send notifications
        # notify_disposer_payout_initiated(marketplace_listing)
        # notify_recycler_transaction_complete(marketplace_listing)

        return Response({
            'success': True,
            'message': 'Item receipt confirmed! Escrow has been released, rewards distributed, and payout initiated.',
            'marketplace_listing': {
                'id': str(marketplace_listing.id),
                'escrow_status': marketplace_listing.escrow_status,
                'released_at': marketplace_listing.released_at.isoformat() if marketplace_listing.released_at else None
            },
            'rewards': {
                'disposer_points': reward_results['disposer_reward'].points if reward_results['disposer_reward'] else 0,
                'recycler_points': reward_results['recycler_reward'].points if reward_results['recycler_reward'] else 0,
                'disposer_referrer_bonus': reward_results['disposer_referrer_reward'].points if reward_results['disposer_referrer_reward'] else 0,
                'recycler_referrer_bonus': reward_results['recycler_referrer_reward'].points if reward_results['recycler_referrer_reward'] else 0,
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
        logger.error(f"Error confirming item receipt for user {request.user.email}: {str(e)}")
        return Response({
            'success': False,
            'message': 'An error occurred while confirming item receipt',
            'error': str(e)
        }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
```

### Step 2.5: Payout Utility

**File:** `apps/payments/utils.py`

```python
"""
Utility functions for payment processing.
"""
from decimal import Decimal
from django.conf import settings
from django.db import transaction
from django.utils import timezone
import logging

from .models import Payment, Payout
from .paystack_client import PaystackClient

logger = logging.getLogger(__name__)


def process_disposer_payout(marketplace_listing):
    """
    Process payout to disposer after successful transaction.

    Args:
        marketplace_listing: MarketplaceListing object with escrow_status='confirmed'

    Returns:
        dict with payout details or error
    """
    try:
        # Get payment record
        payment = marketplace_listing.payment

        # Calculate payout amount (subtract platform fee)
        platform_fee_percentage = settings.PLATFORM_FEE_PERCENTAGE
        platform_fee = (payment.amount * platform_fee_percentage) / Decimal('100')
        net_amount = payment.amount - platform_fee

        # Get disposer
        disposer = marketplace_listing.listing_id.user_id

        # Get or validate disposer bank details
        # TODO: In production, disposer should have saved bank details in their profile
        # For now, we'll assume they have a wallet and we'll credit it
        # In real implementation, you'd use disposer.bank_account_number, disposer.bank_code, etc.

        # Create payout record
        with transaction.atomic():
            payout = Payout.objects.create(
                payment=payment,
                recipient=disposer,
                recipient_account_number='',  # TODO: Get from disposer profile
                recipient_bank_code='',       # TODO: Get from disposer profile
                recipient_account_name=disposer.name,
                amount=payment.amount,
                platform_fee=platform_fee,
                net_amount=net_amount,
                currency='NGN',
                status='pending'
            )

        # TODO: In production, initiate Paystack transfer
        # For now, credit wallet instead
        from apps.wallet.models import Wallet, WalletTransaction

        wallet, _ = Wallet.objects.get_or_create(user=disposer)

        with transaction.atomic():
            # Credit wallet
            from django.db.models import F
            Wallet.objects.filter(id=wallet.id).update(balance=F('balance') + net_amount)
            wallet.refresh_from_db()

            # Create transaction record
            WalletTransaction.objects.create(
                wallet=wallet,
                user=disposer,
                transaction_type='payout',
                amount=net_amount,
                currency='NGN',
                description=f'Payout for listing {marketplace_listing.listing_id.id}',
                payment_method='system',
                status='success',
                metadata={
                    'marketplace_listing_id': str(marketplace_listing.id),
                    'payment_id': str(payment.payment_id),
                    'payout_id': str(payout.payout_id),
                    'gross_amount': str(payment.amount),
                    'platform_fee': str(platform_fee),
                    'net_amount': str(net_amount)
                }
            )

            # Update payout status
            payout.status = 'success'
            payout.is_completed = True
            payout.completed_at = timezone.now()
            payout.paystack_transfer_code = 'WALLET_CREDIT'  # Placeholder
            payout.save()

        logger.info(f"Payout processed: {net_amount} NGN credited to disposer {disposer.email} (wallet)")

        return {
            'success': True,
            'payout_id': payout.payout_id,
            'amount': net_amount,
            'status': 'success',
            'method': 'wallet_credit'
        }

        # TODO: Real Paystack transfer implementation:
        # paystack = PaystackClient()
        # result = paystack.create_transfer_recipient(...)
        # if result['success']:
        #     transfer_result = paystack.initiate_transfer(...)
        #     if transfer_result['success']:
        #         payout.paystack_transfer_code = transfer_result['transfer_code']
        #         payout.status = 'processing'
        #         payout.save()

    except Exception as e:
        logger.error(f"Error processing payout for marketplace listing {marketplace_listing.id}: {str(e)}")
        return {
            'success': False,
            'error': str(e)
        }
```

---

## 📋 Phase 3: URL Routing

### Step 3.1: Create Payment URLs

**File:** `apps/payments/urls.py` (new file)

```python
from django.urls import path
from . import views

urlpatterns = [
    # Payment flow
    path('initialize/', views.initialize_payment, name='initialize-payment'),
    path('verify/', views.verify_payment, name='verify-payment'),
    path('webhook/', views.paystack_webhook, name='paystack-webhook'),

    # Confirmation flow
    path('confirm-release/', views.confirm_item_released, name='confirm-item-released'),
    path('confirm-receipt/', views.confirm_item_received, name='confirm-item-received'),
]
```

### Step 3.2: Register in Main URLs

**File:** `config/urls.py`

```python
urlpatterns = [
    path('admin/', admin.site.urls),
    path('api/v1/wallet/', include('apps.wallet.urls')),
    path('api/v1/users/', include('apps.users.urls')),
    path('api/v1/otp/', include('apps.otp.urls')),
    path('api/v1/contact/', include('apps.contact.urls')),
    path('api/v1/payments/', include('apps.payments.urls')),  # NEW
]
```

---

## 📋 Phase 4: Node.js Integration (OPTIONAL)

### Step 4.1: Create Webhook Endpoint (Django)

**Note:** This is the endpoint that Node.js would call (from the INTEGRATION_REQUIREMENTS.md document).
However, **this is no longer needed** since we're handling everything in Django now.

**File:** `apps/wallet/views.py` (reference only)

```python
@api_view(['POST'])
@permission_classes([IsAuthenticated])  # Or use internal API key
def process_marketplace_transaction(request):
    """
    Legacy webhook for Node.js to trigger reward distribution.

    DEPRECATED: Now handled automatically in confirm_item_received endpoint.

    This endpoint can be removed if Node.js integration is not needed.
    """
    # Implementation from INTEGRATION_REQUIREMENTS.md
    pass
```

**Recommendation:** Remove Node.js webhook dependency and handle everything in Django.

---

## 📋 Phase 5: Testing Strategy

### 5.1 Unit Tests

**File:** `apps/payments/tests.py`

```python
from django.test import TestCase
from django.contrib.auth import get_user_model
from decimal import Decimal

from apps.listings.models import Listing
from apps.marketplace.models import MarketplaceListing
from .models import Payment

User = get_user_model()


class PaymentModelTests(TestCase):
    def setUp(self):
        self.disposer = User.objects.create_user(
            email='disposer@test.com',
            password='test123',
            name='Test Disposer',
            role='disposer'
        )
        self.recycler = User.objects.create_user(
            email='recycler@test.com',
            password='test123',
            name='Test Recycler',
            role='recycler'
        )
        self.listing = Listing.objects.create(
            user_id=self.disposer,
            waste_type='plastic',
            quantity=25.5,
            status='pending',
            reward_estimate=Decimal('255.00'),
            pickup_location={'lat': 0, 'lng': 0}
        )
        self.marketplace_listing = MarketplaceListing.objects.create(
            listing_id=self.listing,
            recycler_id=self.recycler,
            price=Decimal('255.00'),
            escrow_status='pending'
        )

    def test_payment_creation(self):
        payment = Payment.objects.create(
            marketplace_listing=self.marketplace_listing,
            payer=self.recycler,
            amount=Decimal('255.00'),
            paystack_reference='TEST-REF-123'
        )
        self.assertEqual(payment.status, 'pending')
        self.assertFalse(payment.is_verified)

    def test_payment_verification(self):
        payment = Payment.objects.create(
            marketplace_listing=self.marketplace_listing,
            payer=self.recycler,
            amount=Decimal('255.00'),
            paystack_reference='TEST-REF-123'
        )
        payment.status = 'success'
        payment.is_verified = True
        payment.save()

        self.assertEqual(payment.status, 'success')
        self.assertTrue(payment.is_verified)
```

### 5.2 Integration Tests

**File:** `tests/test_payment_flow_e2e.py`

```python
"""
End-to-end test for complete payment flow.
"""
import os
import sys
import django

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'config.settings')
django.setup()

from django.test import TestCase, Client
from django.contrib.auth import get_user_model
from decimal import Decimal
import json

User = get_user_model()


class PaymentFlowE2ETest(TestCase):
    """
    Test complete payment flow from listing creation to payout.
    """

    def setUp(self):
        self.client = Client()

        # Create users
        self.disposer = User.objects.create_user(
            email='disposer_e2e@test.com',
            password='TestPass123!',
            name='Disposer User',
            role='disposer',
            is_verified=True
        )
        self.recycler = User.objects.create_user(
            email='recycler_e2e@test.com',
            password='TestPass123!',
            name='Recycler User',
            role='recycler',
            is_verified=True
        )

        # Login disposer
        response = self.client.post('/api/v1/users/login/', {
            'email': 'disposer_e2e@test.com',
            'password': 'TestPass123!'
        })
        self.disposer_token = response.json()['tokens']['access']

        # Login recycler
        response = self.client.post('/api/v1/users/login/', {
            'email': 'recycler_e2e@test.com',
            'password': 'TestPass123!'
        })
        self.recycler_token = response.json()['tokens']['access']

    def test_complete_payment_flow(self):
        """
        Test the complete flow:
        1. Disposer creates listing
        2. Recycler initializes payment
        3. Payment is verified (simulated)
        4. Disposer confirms item release
        5. Recycler confirms receipt
        6. Escrow released, rewards distributed, payout processed
        """

        # Step 1: Create listing
        from apps.listings.models import Listing
        listing = Listing.objects.create(
            user_id=self.disposer,
            waste_type='plastic',
            quantity=25.5,
            status='pending',
            reward_estimate=Decimal('255.00'),
            pickup_location={'lat': 6.5244, 'lng': 3.3792},
            phone='+2341234567890'
        )

        # Step 2: Recycler initializes payment
        response = self.client.post(
            '/api/v1/payments/initialize/',
            json.dumps({
                'listing_id': str(listing.id),
                'amount': '255.00'
            }),
            content_type='application/json',
            HTTP_AUTHORIZATION=f'Bearer {self.recycler_token}'
        )

        self.assertEqual(response.status_code, 200)
        payment_data = response.json()
        self.assertTrue(payment_data['success'])
        self.assertIn('authorization_url', payment_data)

        payment_reference = payment_data['reference']

        # Step 3: Simulate payment verification
        # In real scenario, user would be redirected to Paystack, pay, and return
        # We'll manually update payment status for testing
        from apps.payments.models import Payment
        payment = Payment.objects.get(paystack_reference=payment_reference)
        payment.status = 'success'
        payment.is_verified = True
        payment.save()

        # Update marketplace listing
        marketplace_listing = payment.marketplace_listing
        marketplace_listing.escrow_status = 'locked'
        marketplace_listing.save()

        # Step 4: Disposer confirms item release
        response = self.client.post(
            '/api/v1/payments/confirm-release/',
            json.dumps({
                'marketplace_listing_id': str(marketplace_listing.id)
            }),
            content_type='application/json',
            HTTP_AUTHORIZATION=f'Bearer {self.disposer_token}'
        )

        self.assertEqual(response.status_code, 200)
        release_data = response.json()
        self.assertTrue(release_data['success'])
        self.assertEqual(release_data['marketplace_listing']['escrow_status'], 'item_released')

        # Step 5: Recycler confirms receipt
        response = self.client.post(
            '/api/v1/payments/confirm-receipt/',
            json.dumps({
                'marketplace_listing_id': str(marketplace_listing.id)
            }),
            content_type='application/json',
            HTTP_AUTHORIZATION=f'Bearer {self.recycler_token}'
        )

        self.assertEqual(response.status_code, 200)
        receipt_data = response.json()
        self.assertTrue(receipt_data['success'])
        self.assertEqual(receipt_data['marketplace_listing']['escrow_status'], 'released')

        # Verify rewards were distributed
        self.assertIn('rewards', receipt_data)
        self.assertEqual(receipt_data['rewards']['disposer_points'], 255)
        self.assertEqual(receipt_data['rewards']['recycler_points'], 255)

        # Verify payout was initiated
        self.assertIn('payout', receipt_data)
        self.assertEqual(receipt_data['payout']['status'], 'success')

        # Verify wallet balances
        from apps.wallet.models import Wallet
        disposer_wallet = Wallet.objects.get(user=self.disposer)
        recycler_wallet = Wallet.objects.get(user=self.recycler)

        self.assertEqual(disposer_wallet.points, 255)  # Activity reward
        self.assertEqual(recycler_wallet.points, 255)  # Activity reward

        print("✅ Complete payment flow test PASSED")
```

### 5.3 Manual Testing Checklist

**Test Scenario 1: Happy Path**
- [ ] Disposer creates listing
- [ ] Recycler views listing
- [ ] Recycler initiates payment
- [ ] Recycler redirected to Paystack
- [ ] Recycler completes payment on Paystack
- [ ] Recycler redirected back with reference
- [ ] System verifies payment automatically
- [ ] Escrow locked, disposer notified
- [ ] Disposer confirms item release
- [ ] Recycler collects item
- [ ] Recycler confirms receipt
- [ ] Escrow released
- [ ] Rewards distributed (255 points each)
- [ ] Payout initiated to disposer
- [ ] Wallet balances updated

**Test Scenario 2: Payment Failure**
- [ ] Recycler initiates payment
- [ ] Recycler cancels on Paystack
- [ ] System shows payment failed
- [ ] Can retry payment

**Test Scenario 3: Dispute**
- [ ] Payment locked
- [ ] Disposer confirms release
- [ ] Recycler does NOT confirm receipt
- [ ] Auto-confirm after 7 days OR
- [ ] Manual dispute resolution

**Test Scenario 4: Refund**
- [ ] Payment locked
- [ ] Transaction cancelled before item release
- [ ] Refund initiated
- [ ] Funds returned to recycler

---

## 📊 Phase 6: Database Migrations

### Step 6.1: Create Migration Files

```bash
# Create migrations
python manage.py makemigrations payments
python manage.py makemigrations marketplace
python manage.py makemigrations wallet

# Review migration files
python manage.py sqlmigrate payments 0001

# Apply migrations
python manage.py migrate

# Verify
python manage.py showmigrations
```

### Step 6.2: Create Indexes for Performance

**File:** `apps/payments/migrations/0002_add_indexes.py`

```python
from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('payments', '0001_initial'),
    ]

    operations = [
        migrations.AddIndex(
            model_name='payment',
            index=models.Index(fields=['status', '-created_at'], name='payment_status_idx'),
        ),
        migrations.AddIndex(
            model_name='payout',
            index=models.Index(fields=['status', '-created_at'], name='payout_status_idx'),
        ),
    ]
```

---

## 📋 Phase 7: Admin Panel Configuration

**File:** `apps/payments/admin.py`

```python
from django.contrib import admin
from .models import Payment, Payout


@admin.register(Payment)
class PaymentAdmin(admin.ModelAdmin):
    list_display = ['payment_id', 'payer', 'amount', 'status', 'is_verified', 'created_at']
    list_filter = ['status', 'payment_provider', 'is_verified', 'created_at']
    search_fields = ['payment_id', 'paystack_reference', 'payer__email', 'payer__name']
    readonly_fields = ['payment_id', 'paystack_reference', 'created_at', 'updated_at', 'verified_at']
    date_hierarchy = 'created_at'

    fieldsets = (
        ('Basic Info', {
            'fields': ('payment_id', 'marketplace_listing', 'payer', 'amount', 'currency')
        }),
        ('Paystack Details', {
            'fields': ('paystack_reference', 'paystack_access_code', 'paystack_authorization_url', 'payment_method')
        }),
        ('Status', {
            'fields': ('status', 'payment_provider', 'is_verified', 'verified_at')
        }),
        ('Webhook Data', {
            'fields': ('paystack_response', 'webhook_received_at'),
            'classes': ('collapse',)
        }),
        ('Error Tracking', {
            'fields': ('retry_count', 'last_error'),
            'classes': ('collapse',)
        }),
        ('Timestamps', {
            'fields': ('created_at', 'updated_at'),
            'classes': ('collapse',)
        }),
    )


@admin.register(Payout)
class PayoutAdmin(admin.ModelAdmin):
    list_display = ['payout_id', 'recipient', 'net_amount', 'status', 'is_completed', 'created_at']
    list_filter = ['status', 'is_completed', 'created_at']
    search_fields = ['payout_id', 'paystack_transfer_code', 'recipient__email', 'recipient__name']
    readonly_fields = ['payout_id', 'created_at', 'updated_at', 'completed_at']
    date_hierarchy = 'created_at'

    fieldsets = (
        ('Basic Info', {
            'fields': ('payout_id', 'payment', 'recipient')
        }),
        ('Bank Details', {
            'fields': ('recipient_account_number', 'recipient_bank_code', 'recipient_account_name')
        }),
        ('Amount', {
            'fields': ('amount', 'platform_fee', 'net_amount', 'currency')
        }),
        ('Paystack Details', {
            'fields': ('paystack_transfer_code', 'paystack_transfer_id')
        }),
        ('Status', {
            'fields': ('status', 'is_completed', 'completed_at')
        }),
        ('Webhook Data', {
            'fields': ('paystack_response',),
            'classes': ('collapse',)
        }),
        ('Error Tracking', {
            'fields': ('retry_count', 'last_error'),
            'classes': ('collapse',)
        }),
        ('Timestamps', {
            'fields': ('created_at', 'updated_at'),
            'classes': ('collapse',)
        }),
    )
```

---

## 🔒 Phase 8: Security Considerations

### 8.1 Idempotency

**Ensure operations are idempotent:**

- Use unique `paystack_reference` for each payment
- Check payment status before processing
- Use database transactions for atomic operations
- Store webhook events for replay protection

### 8.2 Webhook Security

**Verify Paystack webhooks:**

- Always validate `X-Paystack-Signature` header
- Use `hmac.compare_digest()` to prevent timing attacks
- Log all webhook events for audit trail
- Return 200 even on errors to prevent retries

### 8.3 Amount Verification

**Double-check amounts:**

- Verify payment amount matches listing price
- Verify payout amount after platform fee
- Use Decimal for currency calculations
- Log any mismatches

### 8.4 Race Condition Prevention

**Use database locks:**

```python
with transaction.atomic():
    payment = Payment.objects.select_for_update().get(id=payment_id)
    # Process payment
```

---

## 📝 Phase 9: API Documentation Updates

Update [API_DOCUMENTATION.md](API_DOCUMENTATION.md) with new payment endpoints:

```markdown
## 💳 Payment Endpoints

### 1. Initialize Payment
**POST** `/api/v1/payments/initialize/`

Initiates a payment for a marketplace listing.

**Request:**
```json
{
  "listing_id": "uuid",
  "amount": "255.00"
}
```

**Response:**
```json
{
  "success": true,
  "message": "Payment initialized successfully",
  "payment_id": "uuid",
  "authorization_url": "https://checkout.paystack.com/xxxxx",
  "reference": "WW-xxxxx"
}
```

### 2. Verify Payment
**GET** `/api/v1/payments/verify/?reference=WW-xxxxx`

Verifies a payment after Paystack redirect.

### 3. Confirm Item Release
**POST** `/api/v1/payments/confirm-release/`

Disposer confirms item has been released.

### 4. Confirm Item Receipt
**POST** `/api/v1/payments/confirm-receipt/`

Recycler confirms item has been received. Triggers escrow release.

### 5. Paystack Webhook (Internal)
**POST** `/api/v1/payments/webhook/`

Receives Paystack webhook events. Not called by clients.
```

---

## 🎯 SUMMARY: Implementation Checklist

### ✅ Prerequisites
- [ ] Paystack account created
- [ ] Test API keys obtained
- [ ] Webhook URL configured in Paystack dashboard

### ✅ Phase 1: Setup (Day 1)
- [ ] Create `apps/payments` app
- [ ] Add Paystack configuration to settings
- [ ] Create Payment and Payout models
- [ ] Create PaystackClient utility
- [ ] Run migrations

### ✅ Phase 2: Endpoints (Day 2-3)
- [ ] Implement `initialize_payment` endpoint
- [ ] Implement `verify_payment` endpoint
- [ ] Implement `paystack_webhook` handler
- [ ] Implement `confirm_item_released` endpoint
- [ ] Implement `confirm_item_received` endpoint
- [ ] Create payout utility

### ✅ Phase 3: Integration (Day 4)
- [ ] Create payment URLs
- [ ] Register in main URLs
- [ ] Update admin panel
- [ ] Test with Postman

### ✅ Phase 4: Testing (Day 5-6)
- [ ] Write unit tests
- [ ] Write integration tests
- [ ] Manual testing with Paystack sandbox
- [ ] Test webhook handling
- [ ] Test reward distribution
- [ ] Test payout processing

### ✅ Phase 5: Production (Day 7)
- [ ] Switch to production API keys
- [ ] Configure webhook URL
- [ ] Update documentation
- [ ] Monitor logs
- [ ] Deploy to production

---

## 📊 Expected Outcomes

After full implementation:

1. **Recyclers can:**
   - Browse marketplace listings
   - Initiate payment via Paystack
   - Complete checkout securely
   - Confirm item receipt
   - Earn activity points (10 points per kg)
   - Earn referral bonuses (if referred)

2. **Disposers can:**
   - Create listings
   - Receive payment notifications
   - Confirm item release
   - Receive automatic payout to wallet
   - Earn activity points (10 points per kg)
   - Earn referral bonuses (if referred)

3. **System can:**
   - Track all payment transactions
   - Handle escrow flow automatically
   - Distribute rewards on completion
   - Process payouts to disposers
   - Handle webhook events reliably
   - Prevent double-processing
   - Log all events for audit

4. **Admin can:**
   - View all payments in admin panel
   - Track payout status
   - Handle disputes manually
   - Monitor failed transactions
   - View detailed logs

---

## 🚨 Edge Cases & Error Handling

### Payment Failures
- **Card declined:** Show user-friendly error, allow retry
- **Insufficient funds:** Show user-friendly error, allow retry
- **Network timeout:** Verify payment status via webhook, don't show error immediately
- **Duplicate payment:** Check existing payment record, return existing authorization URL

### Payout Failures
- **Invalid bank details:** Notify admin, allow manual correction
- **Insufficient balance:** Retry after 24 hours, notify admin
- **Bank API timeout:** Mark as processing, verify via webhook

### Webhook Issues
- **Signature mismatch:** Reject, log incident
- **Duplicate event:** Check idempotency, skip processing
- **Unknown event:** Log, return 200
- **Processing error:** Log, return 200 to prevent retry storm

### Timeout Scenarios
- **Item not released:** Auto-cancel after 48 hours, refund recycler
- **Item not confirmed:** Auto-confirm after 7 days, release escrow
- **Payout pending:** Retry daily for 7 days, then escalate to admin

---

## 📚 Resources

**Paystack Documentation:**
- Initialize Transaction: https://paystack.com/docs/api/transaction/#initialize
- Verify Transaction: https://paystack.com/docs/api/transaction/#verify
- Transfers: https://paystack.com/docs/api/transfer/
- Webhooks: https://paystack.com/docs/payments/webhooks/

**Django Resources:**
- Transactions: https://docs.djangoproject.com/en/5.2/topics/db/transactions/
- Signals: https://docs.djangoproject.com/en/5.2/topics/signals/

**Security:**
- HMAC: https://docs.python.org/3/library/hmac.html
- Webhook Security: https://paystack.com/docs/payments/webhooks/#verifying-webhooks

---

## ✅ Next Steps

1. **Review this implementation plan**
2. **Get approval from stakeholders**
3. **Set up Paystack account**
4. **Start with Phase 1 (Setup)**
5. **Test thoroughly before production**

---

**Document Status:** Complete Implementation Plan
**Estimated Time:** 7-10 days for full implementation
**Risk Level:** Medium (new payment integration)
**Dependencies:** Paystack account, production API keys
