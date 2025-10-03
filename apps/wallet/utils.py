"""
Utility functions for wallet reward distribution.
"""
from decimal import Decimal
from django.db import transaction
from apps.wallet.models import Wallet, WalletTransaction
from apps.referral.models import Referral
import logging

logger = logging.getLogger(__name__)


def distribute_activity_reward(user, quantity_kg, transaction_type='activity_reward', description=''):
    """
    Distribute activity reward points to a user.

    Args:
        user: User object who should receive the reward
        quantity_kg: Quantity in kilograms (float or Decimal)
        transaction_type: Type of activity reward (default: 'activity_reward')
        description: Description of the reward

    Returns:
        WalletTransaction object or None if failed
    """
    try:
        # Calculate points: 1kg = 10 points
        points = int(Decimal(str(quantity_kg)) * 10)

        if points <= 0:
            logger.warning(f"Invalid points calculation for user {user.email}: quantity={quantity_kg}")
            return None

        with transaction.atomic():
            # Get or create wallet with row lock to prevent race conditions
            wallet, created = Wallet.objects.select_for_update().get_or_create(
                user=user,
                defaults={
                    'balance': Decimal('0.00'),
                    'currency': 'NGN',
                    'points': 0,
                    'is_active': True
                }
            )

            # Update wallet points atomically using F() expression
            from django.db.models import F
            Wallet.objects.filter(id=wallet.id).update(points=F('points') + points)

            # Refresh wallet to get updated points
            wallet.refresh_from_db()

            # Create transaction record
            wallet_transaction = WalletTransaction.objects.create(
                wallet=wallet,
                user=user,
                transaction_type=transaction_type,
                points=points,
                payment_method='system',
                status='success',
                description=description or f'Activity reward: {quantity_kg}kg waste processed'
            )

            logger.info(f"Activity reward distributed: {points} points to {user.email}")
            return wallet_transaction

    except Exception as e:
        logger.error(f"Error distributing activity reward to {user.email}: {str(e)}")
        return None


def distribute_referral_reward(referrer_user, referee_user, referral_obj=None, is_signup=True):
    """
    Distribute referral reward to the referrer.

    Called in two scenarios:
    1. When referee signs up (is_signup=True) - gives 100 points
    2. When referee completes first transaction (is_signup=False) - gives BONUS 100 points

    Args:
        referrer_user: User who referred (receives 100 points)
        referee_user: User who was referred
        referral_obj: Optional Referral object to update status
        is_signup: True if called during signup, False if called on first transaction

    Returns:
        WalletTransaction object or None if failed
    """
    try:
        # Fixed reward: 100 points for referral
        points = 100

        with transaction.atomic():
            # Get or create referrer's wallet with row lock to prevent race conditions
            from django.db.models import F
            wallet, created = Wallet.objects.select_for_update().get_or_create(
                user=referrer_user,
                defaults={
                    'balance': Decimal('0.00'),
                    'currency': 'NGN',
                    'points': 0,
                    'is_active': True
                }
            )

            # Update wallet points atomically using F() expression
            Wallet.objects.filter(id=wallet.id).update(points=F('points') + points)

            # Refresh wallet to get updated points
            wallet.refresh_from_db()

            # Create transaction record with appropriate description
            if is_signup:
                description = f'Referral reward: {referee_user.name or referee_user.email} signed up using your code'
            else:
                description = f'Referral bonus: {referee_user.name or referee_user.email} completed their first transaction'

            wallet_transaction = WalletTransaction.objects.create(
                wallet=wallet,
                user=referrer_user,
                transaction_type='referral_reward',
                points=points,
                payment_method='system',
                status='success',
                description=description
            )

            # Update referral status if provided (only on signup)
            if referral_obj and is_signup:
                referral_obj.status = 'credited'
                referral_obj.referral_reward = points
                referral_obj.save()

            logger.info(f"Referral reward distributed: {points} points to {referrer_user.email} for referring {referee_user.email}")
            return wallet_transaction

    except Exception as e:
        logger.error(f"Error distributing referral reward to {referrer_user.email}: {str(e)}")
        return None


def process_marketplace_rewards(marketplace_listing):
    """
    Process rewards for both disposer (seller) and recycler (buyer) when escrow is released.
    Also handles referral rewards if this is the first transaction for either party.

    Args:
        marketplace_listing: MarketplaceListing object with escrow_status='released'

    Returns:
        dict with results of reward distribution
    """
    try:
        listing = marketplace_listing.listing_id
        disposer = listing.user_id  # Seller
        recycler = marketplace_listing.recycler_id  # Buyer
        quantity_kg = listing.quantity

        results = {
            'disposer_reward': None,
            'recycler_reward': None,
            'disposer_referrer_reward': None,
            'recycler_referrer_reward': None,
            'errors': []
        }

        if not recycler:
            results['errors'].append("No recycler assigned to marketplace listing")
            return results

        # 1. Distribute activity reward to disposer (seller)
        disposer_transaction = distribute_activity_reward(
            user=disposer,
            quantity_kg=quantity_kg,
            description=f'Sold {quantity_kg}kg of {listing.waste_type}'
        )
        results['disposer_reward'] = disposer_transaction

        # 2. Distribute activity reward to recycler (buyer)
        recycler_transaction = distribute_activity_reward(
            user=recycler,
            quantity_kg=quantity_kg,
            description=f'Purchased {quantity_kg}kg of {listing.waste_type}'
        )
        results['recycler_reward'] = recycler_transaction

        # 3. Check and distribute BONUS referral rewards for first transaction
        # Note: Referrer already got 100 points on signup, this gives them ANOTHER 100 points

        # Check if disposer was referred and this is their FIRST transaction
        if disposer.referred_by:
            try:
                referral = Referral.objects.get(
                    referee=disposer,
                    status='credited'  # Already rewarded on signup
                )
                # Count activity transactions - should be exactly 1 (the one we just created)
                activity_count = WalletTransaction.objects.filter(
                    user=disposer,
                    transaction_type='activity_reward'
                ).count()

                if activity_count == 1:  # First transaction - give BONUS reward
                    referrer_reward = distribute_referral_reward(
                        referrer_user=referral.referrer,
                        referee_user=disposer,
                        referral_obj=None,  # Don't update referral status again
                        is_signup=False  # This is the first transaction bonus
                    )
                    results['disposer_referrer_reward'] = referrer_reward
            except Referral.DoesNotExist:
                pass

        # Check if recycler was referred and this is their FIRST transaction
        if recycler.referred_by:
            try:
                referral = Referral.objects.get(
                    referee=recycler,
                    status='credited'  # Already rewarded on signup
                )
                # Count activity transactions - should be exactly 1 (the one we just created)
                activity_count = WalletTransaction.objects.filter(
                    user=recycler,
                    transaction_type='activity_reward'
                ).count()

                if activity_count == 1:  # First transaction - give BONUS reward
                    referrer_reward = distribute_referral_reward(
                        referrer_user=referral.referrer,
                        referee_user=recycler,
                        referral_obj=None,  # Don't update referral status again
                        is_signup=False  # This is the first transaction bonus
                    )
                    results['recycler_referrer_reward'] = referrer_reward
            except Referral.DoesNotExist:
                pass

        logger.info(f"Marketplace rewards processed for listing {listing.id}")
        return results

    except Exception as e:
        logger.error(f"Error processing marketplace rewards: {str(e)}")
        results['errors'].append(str(e))
        return results