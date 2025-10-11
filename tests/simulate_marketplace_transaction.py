#!/usr/bin/env python
"""
Simulate a marketplace transaction to trigger activity rewards.
This creates the necessary Django models to process the reward distribution.
"""
import os
import sys
import django

# Setup Django
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'config.settings')
django.setup()

from apps.users.models import User
from apps.listings.models import Listing
from apps.marketplace.models import MarketplaceListing
from apps.wallet.utils import process_marketplace_rewards
from decimal import Decimal

# Test user emails (production)
DISPOSER_EMAIL = "abdullatifsadiq21+disposer113121@gmail.com"
RECYCLER_EMAIL = "abdullatifsadiq21+recycler112719@gmail.com"
LISTING_ID = "502a6553-73fe-4a3c-a67f-0205141d4e95"

def create_and_process_transaction():
    """
    Create a marketplace transaction record and process rewards
    """
    print("="*80)
    print("SIMULATING MARKETPLACE TRANSACTION")
    print("="*80)

    # Get users
    try:
        disposer = User.objects.get(email=DISPOSER_EMAIL)
        print(f"\n✓ Found Disposer: {disposer.name} ({disposer.id})")
    except User.DoesNotExist:
        print(f"\n✗ Disposer not found: {DISPOSER_EMAIL}")
        print("Note: Users are in production database, not local.")
        print("The listing/marketplace transaction must be completed in production.")
        return False

    try:
        recycler = User.objects.get(email=RECYCLER_EMAIL)
        print(f"✓ Found Recycler: {recycler.name} ({recycler.id})")
    except User.DoesNotExist:
        print(f"\n✗ Recycler not found: {RECYCLER_EMAIL}")
        return False

    # Check if listing exists locally
    try:
        listing = Listing.objects.get(id=LISTING_ID)
        print(f"✓ Found Listing: {listing.id}")
    except Listing.DoesNotExist:
        # Create the listing in local database to simulate
        print(f"\n! Listing not found locally. Creating simulation...")
        listing = Listing.objects.create(
            id=LISTING_ID,
            user_id=disposer,
            waste_type='plastic',
            quantity=25.5,
            status='completed',
            reward_estimate=Decimal('255.00'),
            final_reward=Decimal('255.00'),
            pickup_location='Lagos'
        )
        print(f"✓ Created Listing: {listing.id} (25.5kg plastic)")

    # Check if marketplace listing exists
    marketplace_listing, created = MarketplaceListing.objects.get_or_create(
        listing_id=listing,
        defaults={
            'recycler_id': recycler,
            'price': Decimal('255.00'),
            'escrow_status': 'released'  # This triggers reward distribution
        }
    )

    if created:
        print(f"✓ Created MarketplaceListing: {marketplace_listing.id}")
    else:
        # Update to released status
        marketplace_listing.recycler_id = recycler
        marketplace_listing.escrow_status = 'released'
        marketplace_listing.save()
        print(f"✓ Updated MarketplaceListing: {marketplace_listing.id} -> released")

    # Get initial wallet balances
    from apps.wallet.models import Wallet

    disposer_wallet = Wallet.objects.get(user=disposer)
    recycler_wallet = Wallet.objects.get(user=recycler)

    print(f"\nInitial Balances:")
    print(f"  Disposer: {disposer_wallet.points} points")
    print(f"  Recycler: {recycler_wallet.points} points")

    # Process the marketplace rewards
    print(f"\nProcessing marketplace rewards...")
    results = process_marketplace_rewards(marketplace_listing)

    # Check results
    print(f"\nResults:")
    print(f"  Disposer Reward: {results['disposer_reward']}")
    print(f"  Recycler Reward: {results['recycler_reward']}")
    print(f"  Disposer Referrer Bonus: {results['disposer_referrer_reward']}")
    print(f"  Recycler Referrer Bonus: {results['recycler_referrer_reward']}")

    if results['errors']:
        print(f"\n  Errors: {results['errors']}")

    # Get final balances
    disposer_wallet.refresh_from_db()
    recycler_wallet.refresh_from_db()

    print(f"\nFinal Balances:")
    print(f"  Disposer: {disposer_wallet.points} points (+{disposer_wallet.points - disposer_wallet.points})")
    print(f"  Recycler: {recycler_wallet.points} points")

    # Get transaction history
    from apps.wallet.models import WalletTransaction

    print(f"\nDisposer Transactions:")
    for txn in WalletTransaction.objects.filter(user=disposer).order_by('-created_at')[:5]:
        print(f"  - {txn.transaction_type}: {txn.points} points | {txn.description}")

    print(f"\nRecycler Transactions:")
    for txn in WalletTransaction.objects.filter(user=recycler).order_by('-created_at')[:5]:
        print(f"  - {txn.transaction_type}: {txn.points} points | {txn.description}")

    print("\n" + "="*80)
    print("SIMULATION COMPLETE")
    print("="*80)

    return True

if __name__ == "__main__":
    try:
        success = create_and_process_transaction()
        if not success:
            print("\n⚠ Could not complete simulation")
            print("This is expected if users are only in production database.")
            print("\nTo test activity rewards in production:")
            print("1. A recycler must accept/purchase the listing in the Node.js service")
            print("2. The escrow must be released (transaction completed)")
            print("3. The Node.js service should call Django's webhook to trigger rewards")
    except Exception as e:
        print(f"\n✗ Error: {e}")
        import traceback
        traceback.print_exc()
