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
        try:
            payment = marketplace_listing.payment
        except Payment.DoesNotExist:
            logger.error(f"No payment found for marketplace listing {marketplace_listing.id}")
            return {
                'success': False,
                'error': 'No payment record found for this transaction'
            }

        # Calculate payout amount (subtract platform fee)
        platform_fee_percentage = settings.PLATFORM_FEE_PERCENTAGE
        platform_fee = (payment.amount * platform_fee_percentage) / Decimal('100')
        net_amount = payment.amount - platform_fee

        # Get disposer
        disposer = marketplace_listing.listing_id.user_id

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

        # For now, credit wallet instead of real bank transfer
        # TODO: In production, use Paystack Transfer API for real bank transfers
        from apps.wallet.models import Wallet, WalletTransaction
        from django.db.models import F

        wallet, _ = Wallet.objects.get_or_create(user=disposer)

        with transaction.atomic():
            # Credit wallet
            Wallet.objects.filter(wallet_id=wallet.wallet_id).update(balance=F('balance') + net_amount)
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

        # TODO: Real Paystack transfer implementation (for future use):
        # paystack = PaystackClient()
        # result = paystack.create_transfer_recipient(
        #     account_number=disposer.bank_account_number,
        #     bank_code=disposer.bank_code,
        #     account_name=disposer.name
        # )
        # if result['success']:
        #     transfer_result = paystack.initiate_transfer(
        #         amount=net_amount,
        #         recipient_code=result['recipient_code'],
        #         reason=f'Payout for listing {marketplace_listing.listing_id.id}',
        #         reference=f'PAYOUT-{payout.payout_id}'
        #     )
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
