# 🏗️ WasteWorth Escrow Payment Architecture Review & Implementation Plan

**Date:** October 8, 2025
**Status:** Comprehensive System Analysis Complete
**Objective:** Full Escrow + Paystack Integration with Reward Engine

---

## 📊 EXECUTIVE SUMMARY

The WasteWorth platform is a **dual-backend recycling marketplace** connecting **Disposers** (waste item sellers) and **Recyclers** (waste item buyers). The system currently has:

✅ **Functional Components:**
- User authentication with JWT & OTP verification
- Wallet system with cash balance and points
- Referral reward system (100 points on signup + 100 bonus on first transaction)
- Activity reward system (10 points per kg of waste)
- Dashboard endpoints for both user types
- Listing management (Node.js service)

❌ **Missing Critical Components:**
- Complete escrow payment flow
- Paystack Standard Checkout integration
- Payment webhook verification
- Automated payout to disposers
- Transaction status tracking
- Payment failure handling
- Django-Node webhook communication for payment events

---

## 🎯 PART 1: CURRENT SYSTEM ARCHITECTURE

### 1.1 Technology Stack

**Backend 1: Django (Python)**
- **Framework:** Django 5.2.6 + Django REST Framework
- **Database:** SQLite (development) / PostgreSQL (production recommended)
- **Authentication:** JWT (django-rest-framework-simplejwt)
- **Purpose:** User management, authentication, wallet, rewards, payments

**Backend 2: Node.js (Express)**
- **Framework:** Express.js
- **Database:** Shared database with Django (same DB, different models)
- **Authentication:** JWT (same tokens as Django)
- **Purpose:** Item listings, marketplace matching, real-time features
- **URL:** https://wasteworth-backend-express.onrender.com
- **Communication:** Internal API key for service-to-service calls

### 1.2 Database Models (Django)

#### 1.2.1 User Model
**Location:** [apps/users/models.py](apps/users/models.py)

```python
class User(AbstractUser):
    id = UUIDField (primary_key)
    name = CharField(max_length=255)
    email = EmailField(unique=True)
    phone = CharField(max_length=20, unique=True)
    is_verified = BooleanField(default=False)
    role = CharField(choices=['disposer', 'recycler', 'admin'])
    address_location = JSONField
    referral_code = CharField(max_length=10, unique=True)
    referred_by = CharField(max_length=10)  # Referral code used during signup
    created_at = DateTimeField
    updated_at = DateTimeField
```

**Key Features:**
- Auto-generates unique 8-character referral code
- Provides referral link: `{FRONTEND_URL}/signup?ref={referral_code}`
- Tracks who referred them via `referred_by` field

#### 1.2.2 Wallet Model
**Location:** [apps/wallet/models.py](apps/wallet/models.py)

```python
class Wallet(models.Model):
    wallet_id = UUIDField (primary_key)
    user = OneToOneField(User)
    balance = DecimalField(max_digits=10, decimal_places=2, default=0.00)
    currency = CharField(max_length=3, default='NGN')
    points = IntegerField(default=0)
    is_active = BooleanField(default=True)
    created_at = DateTimeField
    updated_at = DateTimeField
```

**Key Features:**
- One wallet per user (auto-created on first access)
- Tracks both **cash balance** (Naira) and **eco-points**
- Points are primary reward mechanism

#### 1.2.3 WalletTransaction Model
**Location:** [apps/wallet/models.py](apps/wallet/models.py)

```python
class WalletTransaction(models.Model):
    transaction_id = UUIDField (primary_key)
    wallet = ForeignKey(Wallet)
    user = ForeignKey(User)
    transaction_type = CharField(choices=[
        'credit', 'debit', 'payout', 'referral_reward',
        'activity_reward', 'redeem', 'deposit',
        'withdrawal', 'refund'
    ])
    amount = DecimalField (nullable)  # For cash transactions
    points = IntegerField (nullable)  # For point transactions
    currency = CharField(default='NGN')
    description = CharField(max_length=255)
    reference = CharField(unique=True)  # Auto-generated: WW{transaction_id[:8]}
    payment_method = CharField(choices=[
        'bank', 'mobileMoney', 'airtime', 'voucher',
        'system', 'card', 'referral_reward',
        'activity_reward', 'redeem'
    ])
    status = CharField(choices=['pending', 'processing', 'success', 'failed', 'cancelled'])
    metadata = JSONField (nullable)  # Additional transaction data
    created_at = DateTimeField
```

**Key Features:**
- Tracks all wallet movements (cash + points)
- Unique reference for idempotency
- Status tracking for async payment operations
- Metadata field for payment gateway references

#### 1.2.4 Listing Model
**Location:** [apps/listings/models.py](apps/listings/models.py)

```python
class Listing(models.Model):
    id = UUIDField (primary_key)
    user_id = ForeignKey(User)  # Disposer who created listing
    collector_id = ForeignKey(User, nullable=True)  # Recycler assigned
    title = CharField(max_length=255, nullable=True)
    waste_type = CharField(choices=['plastic', 'glass', 'paper'])
    quantity = FloatField  # In kilograms
    status = CharField(choices=['pending', 'accepted', 'in-progress', 'completed', 'cancelled'])
    reward_estimate = DecimalField(max_digits=10, decimal_places=2)
    image_url = URLField (nullable)
    final_reward = DecimalField (nullable)
    pickup_location = JSONField
    phone = CharField(max_length=20, nullable=True)
    created_at = DateTimeField
    updated_at = DateTimeField
```

**Key Features:**
- Created by disposers (waste item sellers)
- Accepted by recyclers (waste item buyers)
- Quantity determines points: 1kg = 10 points
- Status tracks lifecycle: pending → accepted → in-progress → completed

#### 1.2.5 MarketplaceListing Model
**Location:** [apps/marketplace/models.py](apps/marketplace/models.py)

```python
class MarketplaceListing(models.Model):
    id = UUIDField (primary_key)
    listing_id = ForeignKey(Listing)
    recycler_id = ForeignKey(User, nullable=True)  # Buyer
    price = DecimalField(max_digits=10, decimal_places=2)
    escrow_status = CharField(choices=['pending', 'locked', 'released', 'cancelled'])
    created_at = DateTimeField
```

**Key Features:**
- Links listing to marketplace transaction
- Tracks recycler who purchased
- **`escrow_status` is THE critical field for payment flow**
  - `pending` - No payment yet
  - `locked` - Payment received, funds held in escrow
  - `released` - Item confirmed, funds released to disposer, **TRIGGERS REWARDS**
  - `cancelled` - Transaction cancelled, refund initiated

#### 1.2.6 Referral Model
**Location:** [apps/referral/models.py](apps/referral/models.py)

```python
class Referral(models.Model):
    id = UUIDField (primary_key)
    referrer = ForeignKey(User, related_name='referrals_made')  # Who referred
    referee = ForeignKey(User, related_name='referrals_received')  # Who signed up
    referral_reward = IntegerField(default=0)
    status = CharField(choices=['pending', 'credited'])
    created_at = DateTimeField
```

**Key Features:**
- Created when new user signs up with `referred_by` code
- Status set to 'credited' when first reward (100 points) is distributed
- Referrer gets BONUS 100 points on referee's first transaction

---

### 1.3 Reward Engine Implementation

**Location:** [apps/wallet/utils.py](apps/wallet/utils.py)

#### 1.3.1 Referral Reward System

**Function:** `distribute_referral_reward(referrer_user, referee_user, referral_obj, is_signup)`

**Trigger Points:**
1. **On Signup** (`is_signup=True`)
   - Called from `UserSignupSerializer.create()`
   - Gives referrer **100 points immediately**
   - Creates Referral record with status='pending'
   - Updates status to 'credited'

2. **On First Transaction** (`is_signup=False`)
   - Called from `process_marketplace_rewards()`
   - Gives referrer **BONUS 100 points**
   - Checks if referee has exactly 1 activity transaction
   - Does NOT update Referral record (already credited)

**Total Potential:** 200 points per successful referral

**Implementation:**
```python
def distribute_referral_reward(referrer_user, referee_user, referral_obj=None, is_signup=True):
    points = 100

    with transaction.atomic():
        wallet, _ = Wallet.objects.select_for_update().get_or_create(user=referrer_user)
        Wallet.objects.filter(id=wallet.id).update(points=F('points') + points)

        description = (
            f'Referral reward: {referee_user.name} signed up using your code' if is_signup
            else f'Referral bonus: {referee_user.name} completed their first transaction'
        )

        WalletTransaction.objects.create(
            wallet=wallet,
            user=referrer_user,
            transaction_type='referral_reward',
            points=points,
            payment_method='system',
            status='success',
            description=description
        )

        if referral_obj and is_signup:
            referral_obj.status = 'credited'
            referral_obj.referral_reward = points
            referral_obj.save()
```

**Safety Features:**
- Row-level locking with `select_for_update()` prevents race conditions
- Atomic updates using `F()` expressions
- Database transaction wrapper ensures all-or-nothing

#### 1.3.2 Activity Reward System

**Function:** `distribute_activity_reward(user, quantity_kg, transaction_type, description)`

**Formula:** 1 kg waste = 10 points

**Trigger:** When marketplace transaction completes (escrow released)

**Recipients:**
- **Disposer (seller):** Points for selling waste
- **Recycler (buyer):** Points for collecting waste

**Implementation:**
```python
def distribute_activity_reward(user, quantity_kg, transaction_type='activity_reward', description=''):
    points = int(Decimal(str(quantity_kg)) * 10)

    with transaction.atomic():
        wallet, _ = Wallet.objects.select_for_update().get_or_create(user=user)
        Wallet.objects.filter(id=wallet.id).update(points=F('points') + points)

        WalletTransaction.objects.create(
            wallet=wallet,
            user=user,
            transaction_type=transaction_type,
            points=points,
            payment_method='system',
            status='success',
            description=description or f'Activity reward: {quantity_kg}kg waste processed'
        )
```

#### 1.3.3 Marketplace Reward Orchestrator

**Function:** `process_marketplace_rewards(marketplace_listing)`

**Called When:** `escrow_status` changes to `'released'`

**Workflow:**
1. Extract listing, disposer, recycler, quantity from marketplace_listing
2. Award activity points to disposer (seller)
3. Award activity points to recycler (buyer)
4. Check if disposer was referred AND this is their first transaction → award bonus to referrer
5. Check if recycler was referred AND this is their first transaction → award bonus to referrer

**Implementation:**
```python
@transaction.atomic
def process_marketplace_rewards(marketplace_listing):
    listing = marketplace_listing.listing_id
    disposer = listing.user_id
    recycler = marketplace_listing.recycler_id
    quantity_kg = listing.quantity

    results = {
        'disposer_reward': None,
        'recycler_reward': None,
        'disposer_referrer_reward': None,
        'recycler_referrer_reward': None,
        'errors': []
    }

    # 1. Reward disposer
    results['disposer_reward'] = distribute_activity_reward(
        user=disposer,
        quantity_kg=quantity_kg,
        description=f'Sold {quantity_kg}kg of {listing.waste_type}'
    )

    # 2. Reward recycler
    results['recycler_reward'] = distribute_activity_reward(
        user=recycler,
        quantity_kg=quantity_kg,
        description=f'Purchased {quantity_kg}kg of {listing.waste_type}'
    )

    # 3. Check for referral bonus (disposer)
    if disposer.referred_by:
        referral = Referral.objects.filter(referee=disposer, status='credited').first()
        if referral:
            activity_count = WalletTransaction.objects.filter(
                user=disposer,
                transaction_type='activity_reward'
            ).count()
            if activity_count == 1:  # First transaction
                results['disposer_referrer_reward'] = distribute_referral_reward(
                    referrer_user=referral.referrer,
                    referee_user=disposer,
                    is_signup=False
                )

    # 4. Check for referral bonus (recycler) - same logic
    # ...

    return results
```

**Safety Features:**
- Wrapped in `@transaction.atomic` decorator
- If any reward fails, all rewards rollback
- Idempotent: can be called multiple times safely

---

### 1.4 Dashboard Implementations

**Location:** [apps/users/views.py](apps/users/views.py)

#### 1.4.1 Disposer Dashboard

**Endpoint:** `GET /api/v1/users/disposer-dashboard/`

**Returns:**
```json
{
  "user": {
    "id": "uuid",
    "name": "John Doe",
    "email": "john@example.com",
    "phone": "+1234567890",
    "role": "disposer",
    "address_location": {"lat": 40.7128, "lng": -74.0060},
    "wallet_balance": "150.00",
    "referral_code": "ABC123DE",
    "referral_link": "https://wasteworth.com/signup?ref=ABC123DE",
    "created_at": "2025-01-15T10:30:00Z"
  },
  "stats": {
    "total_listings": 12,
    "sold_listings": 8,
    "recent_posts": [...]
  }
}
```

**Data Sources:**
- User data: Django `User` table
- Total listings: Node `Listing` table (COUNT)
- Sold listings: Node `MarketplaceListing` table (COUNT WHERE escrow_status='released')
- Recent posts: Node `Listing` table (ORDER BY created_at DESC LIMIT 5)

**Note:** Direct database queries, no API calls to Node service

#### 1.4.2 Recycler Dashboard

**Endpoint:** `GET /api/v1/users/recycler-dashboard/`

**Returns:**
```json
{
  "user": {...},  // Same as disposer
  "stats": {
    "total_kg_collected": 156.75,
    "total_points": 1250,
    "recent_posts": [...]  // System-wide listings available
  }
}
```

**Data Sources:**
- User data: Django `User` table
- Total kg collected: SUM of `Listing.quantity` WHERE `MarketplaceListing.recycler_id=user` AND `escrow_status='released'`
- Total points: Django `Wallet.points`
- Recent posts: Node `Listing` table (system-wide, status='pending' or 'accepted')

---

### 1.5 Service Communication Pattern

**Django → Node.js:**
- **Method:** HTTP requests with dual authentication
- **Headers:**
  ```javascript
  {
    "Authorization": "Bearer {user_jwt_token}",  // User authentication
    "api_key": "Bearer {INTERNAL_API_KEY}",     // Service authentication
    "Content-Type": "application/json"
  }
  ```
- **Use Cases:** Fetching listings, notifications (legacy, now replaced with direct DB queries)

**Node.js → Django:**
- **Current:** ❌ Not implemented
- **Needed:** Webhook to trigger reward distribution on marketplace events
- **Missing Endpoint:** `/api/v1/wallet/marketplace-transaction/`

---

## 🔍 PART 2: GAP ANALYSIS

### 2.1 What's Working ✅

| Component | Status | Notes |
|-----------|--------|-------|
| User Authentication | ✅ Complete | JWT + OTP verification |
| Wallet Management | ✅ Complete | Balance, points, transactions |
| Referral System | ✅ Complete | 100 + 100 bonus points |
| Activity Rewards | ✅ Logic Ready | Function exists, not triggered automatically |
| Dashboard APIs | ✅ Complete | Both disposer and recycler |
| Listing Management | ✅ Complete | Node.js service functional |
| Point Redemption | ✅ Complete | Airtime, voucher redemption |
| Transaction History | ✅ Complete | Paginated with filters |

### 2.2 What's Missing ❌

#### 2.2.1 Payment Infrastructure

| Component | Status | Impact |
|-----------|--------|--------|
| **Paystack Integration** | ❌ Missing | Cannot accept payments |
| **Escrow Payment Flow** | ❌ Missing | No buyer payment mechanism |
| **Payment Verification Webhook** | ❌ Missing | Cannot confirm payments |
| **Automated Payout** | ❌ Missing | Cannot pay disposers |
| **Payment Transaction Model** | ❌ Missing | No payment tracking |
| **Refund Handling** | ❌ Missing | No cancellation flow |

#### 2.2.2 Integration Gaps

| Component | Status | Impact |
|-----------|--------|--------|
| **Node→Django Webhook** | ❌ Missing | Rewards not triggered automatically |
| **Escrow Status Updates** | ❌ Manual | No automated status transitions |
| **Payment Notifications** | ❌ Missing | Users not informed of payment status |
| **Transaction Idempotency** | ❌ Partial | Risk of duplicate processing |

#### 2.2.3 Database Schema Gaps

| Field/Table | Current | Needed | Priority |
|-------------|---------|--------|----------|
| Payment transaction table | ❌ None | ✅ New table | High |
| Paystack reference in WalletTransaction | ❌ Only generic metadata | ✅ Dedicated field | High |
| Payment status tracking | ❌ Basic status enum | ✅ Enhanced states | Medium |
| Payout records | ❌ None | ✅ Separate model | Medium |
| Transaction retry mechanism | ❌ None | ✅ Retry count field | Low |

### 2.3 Critical Issues

#### 2.3.1 **Rewards Not Triggered Automatically**
- **Current:** Rewards only distributed if `process_marketplace_rewards()` called manually
- **Problem:** Node.js doesn't call Django when transaction completes
- **Impact:** Users complete transactions but don't receive points
- **Solution:** Create webhook endpoint for Node to call

#### 2.3.2 **No Payment Gateway Integration**
- **Current:** `escrow_status` field exists but no way to populate it
- **Problem:** No payment mechanism for recyclers to pay
- **Impact:** System cannot process real transactions
- **Solution:** Integrate Paystack Standard Checkout

#### 2.3.3 **No Disposer Payout Mechanism**
- **Current:** No way to release funds to disposer after item confirmed
- **Problem:** Disposers can't withdraw earnings
- **Impact:** One-sided marketplace (buyers pay, sellers can't receive)
- **Solution:** Implement Paystack Transfer API for payouts

#### 2.3.4 **Transaction Verification Gap**
- **Current:** No webhook to verify Paystack payments
- **Problem:** Cannot confirm payment actually succeeded
- **Impact:** Risk of fraud, failed payments not detected
- **Solution:** Implement Paystack webhook handler with signature verification

---

## 🏗️ PART 3: COMPLETE ESCROW PAYMENT ARCHITECTURE

### 3.1 Escrow Flow Overview

```
┌─────────────┐         ┌──────────────┐         ┌─────────────┐
│  RECYCLER   │         │   PAYSTACK   │         │  DISPOSER   │
│  (Buyer)    │         │   (Escrow)   │         │  (Seller)   │
└──────┬──────┘         └───────┬──────┘         └──────┬──────┘
       │                        │                       │
       │ 1. Initiate Payment    │                       │
       ├───────────────────────>│                       │
       │                        │                       │
       │ 2. Redirect to Checkout│                       │
       │<───────────────────────┤                       │
       │                        │                       │
       │ 3. Complete Payment    │                       │
       ├───────────────────────>│                       │
       │                        │                       │
       │                 4. Webhook (payment.success)   │
       │                        ├──────────────────────>│
       │                        │ Django: Lock Escrow   │
       │                        │                       │
       │ 5. Collect Item        │                       │
       ├───────────────────────────────────────────────>│
       │                        │                       │
       │ 6. Confirm Receipt     │                       │
       ├───────────────────────>│ Django: Release Escrow│
       │                        │ Distribute Rewards    │
       │                        │                       │
       │                 7. Transfer Funds              │
       │                        ├──────────────────────>│
       │                        │ Paystack Transfer API │
       │                        │                       │
```

### 3.2 Escrow States

| State | Description | Next States | Actions |
|-------|-------------|-------------|---------|
| **pending** | Initial state, no payment yet | locked, cancelled | None |
| **payment_initiated** | Recycler started checkout | locked, failed, cancelled | Paystack checkout page shown |
| **locked** | Payment received, funds in escrow | released, refunded, cancelled | Notify disposer to release item |
| **item_released** | Disposer confirmed item given | confirmed, disputed | Wait for recycler confirmation |
| **confirmed** | Recycler confirmed receipt | released | Trigger payout + rewards |
| **released** | Funds paid to disposer, rewards distributed | None (final) | Transaction complete |
| **refunded** | Payment returned to recycler | None (final) | Issue refund via Paystack |
| **failed** | Payment failed | pending, cancelled | Allow retry |
| **cancelled** | Transaction cancelled | None (final) | Cleanup |
| **disputed** | Issue raised | refunded, released | Manual intervention |

### 3.3 Database Schema Changes

#### 3.3.1 New Model: Payment

**Location:** `apps/payments/models.py` (new app)

```python
from django.db import models
from django.conf import settings
import uuid

class Payment(models.Model):
    """
    Tracks payment transactions via Paystack.
    One-to-one with MarketplaceListing.
    """

    PAYMENT_STATUS_CHOICES = [
        ('pending', 'Pending'),
        ('processing', 'Processing'),
        ('success', 'Success'),
        ('failed', 'Failed'),
        ('refunded', 'Refunded'),
    ]

    PAYMENT_PROVIDER_CHOICES = [
        ('paystack', 'Paystack'),
        ('manual', 'Manual'),  # For testing
    ]

    # Primary keys
    payment_id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    marketplace_listing = models.OneToOneField(
        'marketplace.MarketplaceListing',
        on_delete=models.CASCADE,
        related_name='payment'
    )

    # Payer info
    payer = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.CASCADE,
        related_name='payments_made'
    )

    # Payment details
    amount = models.DecimalField(max_digits=10, decimal_places=2)
    currency = models.CharField(max_length=3, default='NGN')
    payment_method = models.CharField(max_length=50, blank=True)  # card, bank, ussd

    # Paystack references
    paystack_reference = models.CharField(max_length=100, unique=True)
    paystack_access_code = models.CharField(max_length=100, blank=True)
    paystack_authorization_url = models.URLField(blank=True)

    # Status tracking
    status = models.CharField(max_length=20, choices=PAYMENT_STATUS_CHOICES, default='pending')
    payment_provider = models.CharField(max_length=20, choices=PAYMENT_PROVIDER_CHOICES, default='paystack')

    # Verification
    is_verified = models.BooleanField(default=False)
    verified_at = models.DateTimeField(null=True, blank=True)

    # Webhook data
    paystack_response = models.JSONField(null=True, blank=True)
    webhook_received_at = models.DateTimeField(null=True, blank=True)

    # Retry handling
    retry_count = models.IntegerField(default=0)
    last_error = models.TextField(blank=True)

    # Timestamps
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        db_table = 'payments'
        indexes = [
            models.Index(fields=['paystack_reference']),
            models.Index(fields=['status', '-created_at']),
            models.Index(fields=['payer', '-created_at']),
        ]

    def __str__(self):
        return f"Payment {self.payment_id} - {self.amount} {self.currency} ({self.status})"
```

#### 3.3.2 New Model: Payout

**Location:** `apps/payments/models.py`

```python
class Payout(models.Model):
    """
    Tracks payout transfers to disposers via Paystack Transfer API.
    Created when escrow is released.
    """

    PAYOUT_STATUS_CHOICES = [
        ('pending', 'Pending'),
        ('processing', 'Processing'),
        ('success', 'Success'),
        ('failed', 'Failed'),
        ('reversed', 'Reversed'),
    ]

    # Primary keys
    payout_id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    payment = models.OneToOneField(Payment, on_delete=models.CASCADE, related_name='payout')

    # Recipient info
    recipient = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.CASCADE,
        related_name='payouts_received'
    )
    recipient_account_number = models.CharField(max_length=20)
    recipient_bank_code = models.CharField(max_length=10)
    recipient_account_name = models.CharField(max_length=255)

    # Payout details
    amount = models.DecimalField(max_digits=10, decimal_places=2)
    platform_fee = models.DecimalField(max_digits=10, decimal_places=2, default=0.00)
    net_amount = models.DecimalField(max_digits=10, decimal_places=2)  # amount - platform_fee
    currency = models.CharField(max_length=3, default='NGN')

    # Paystack references
    paystack_transfer_code = models.CharField(max_length=100, unique=True, blank=True)
    paystack_transfer_id = models.CharField(max_length=100, blank=True)

    # Status tracking
    status = models.CharField(max_length=20, choices=PAYOUT_STATUS_CHOICES, default='pending')

    # Verification
    is_completed = models.BooleanField(default=False)
    completed_at = models.DateTimeField(null=True, blank=True)

    # Webhook data
    paystack_response = models.JSONField(null=True, blank=True)

    # Retry handling
    retry_count = models.IntegerField(default=0)
    last_error = models.TextField(blank=True)

    # Timestamps
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        db_table = 'payouts'
        indexes = [
            models.Index(fields=['paystack_transfer_code']),
            models.Index(fields=['status', '-created_at']),
            models.Index(fields=['recipient', '-created_at']),
        ]

    def __str__(self):
        return f"Payout {self.payout_id} - {self.net_amount} {self.currency} to {self.recipient.name}"
```

#### 3.3.3 Update: MarketplaceListing Model

**Location:** [apps/marketplace/models.py](apps/marketplace/models.py)

```python
class MarketplaceListing(models.Model):
    # Existing fields...

    # NEW: Enhanced escrow status
    ESCROW_STATUS_CHOICES = [
        ('pending', 'Pending'),
        ('payment_initiated', 'Payment Initiated'),
        ('locked', 'Locked'),  # Payment received
        ('item_released', 'Item Released'),  # Disposer confirmed
        ('confirmed', 'Confirmed'),  # Recycler confirmed receipt
        ('released', 'Released'),  # Funds paid out, rewards distributed
        ('refunded', 'Refunded'),
        ('failed', 'Failed'),
        ('cancelled', 'Cancelled'),
        ('disputed', 'Disputed'),
    ]

    escrow_status = models.CharField(
        max_length=20,
        choices=ESCROW_STATUS_CHOICES,
        default='pending'
    )

    # NEW: Timestamps for state transitions
    payment_initiated_at = models.DateTimeField(null=True, blank=True)
    payment_locked_at = models.DateTimeField(null=True, blank=True)
    item_released_at = models.DateTimeField(null=True, blank=True)
    confirmed_at = models.DateTimeField(null=True, blank=True)
    released_at = models.DateTimeField(null=True, blank=True)

    # NEW: Confirmation tracking
    disposer_confirmed = models.BooleanField(default=False)
    recycler_confirmed = models.BooleanField(default=False)

    # NEW: Automatic timeout
    auto_confirm_deadline = models.DateTimeField(null=True, blank=True)

    class Meta:
        db_table = 'marketplace_listings'
        indexes = [
            models.Index(fields=['escrow_status', '-created_at']),
            models.Index(fields=['auto_confirm_deadline']),
        ]
```

#### 3.3.4 Update: WalletTransaction Metadata

**Enhancement:** Use `metadata` field to store payment references

```python
# Example metadata structure
{
    "payment_id": "uuid",
    "paystack_reference": "T123456789",
    "marketplace_listing_id": "uuid",
    "listing_id": "uuid",
    "transaction_type": "escrow_payment",
    "counterparty_user_id": "uuid",  # Disposer for recycler payments, vice versa
    "quantity_kg": 25.5,
    "waste_type": "plastic"
}
```

---

## 🚀 PART 4: IMPLEMENTATION ROADMAP

### Phase 1: Payment Infrastructure Setup

#### Step 1.1: Create Payments App

```bash
cd apps
python manage.py startapp payments
```

**Register in `config/settings.py`:**
```python
INSTALLED_APPS = [
    # ...existing apps...
    'apps.payments',
]
```

#### Step 1.2: Add Paystack Configuration

**File:** `config/settings.py`

```python
# ===================================================================
# PAYSTACK CONFIGURATION
# ===================================================================

PAYSTACK_SECRET_KEY = config('PAYSTACK_SECRET_KEY', default='')
PAYSTACK_PUBLIC_KEY = config('PAYSTACK_PUBLIC_KEY', default='')
PAYSTACK_CALLBACK_URL = config('PAYSTACK_CALLBACK_URL', default='')
PAYSTACK_WEBHOOK_SECRET = config('PAYSTACK_WEBHOOK_SECRET', default='')

# Paystack API endpoints
PAYSTACK_BASE_URL = 'https://api.paystack.co'
PAYSTACK_INITIALIZE_URL = f'{PAYSTACK_BASE_URL}/transaction/initialize'
PAYSTACK_VERIFY_URL = f'{PAYSTACK_BASE_URL}/transaction/verify'
PAYSTACK_TRANSFER_URL = f'{PAYSTACK_BASE_URL}/transfer'
PAYSTACK_TRANSFER_RECIPIENT_URL = f'{PAYSTACK_BASE_URL}/transferrecipient'

# Platform fee (percentage)
PLATFORM_FEE_PERCENTAGE = Decimal('5.0')  # 5% platform fee
```

**Update `.env`:**
```env
PAYSTACK_SECRET_KEY=sk_test_xxxxxxxxxxxxxxxxxxxxx
PAYSTACK_PUBLIC_KEY=pk_test_xxxxxxxxxxxxxxxxxxxxx
PAYSTACK_CALLBACK_URL=https://yourfrontend.com/payment/callback
PAYSTACK_WEBHOOK_SECRET=whsec_xxxxxxxxxxxxxxxxxxxxx
```

#### Step 1.3: Create Models

```bash
# Create migrations
python manage.py makemigrations payments
python manage.py makemigrations marketplace  # For updated escrow status

# Apply migrations
python manage.py migrate
```

#### Step 1.4: Create Paystack Utility

**File:** `apps/payments/paystack_client.py`

```python
"""
Paystack API client for payment operations.
"""
import requests
import hashlib
import hmac
from decimal import Decimal
from django.conf import settings
import logging

logger = logging.getLogger(__name__)


class PaystackClient:
    """
    Client for interacting with Paystack API.
    Handles payment initialization, verification, and transfers.
    """

    def __init__(self):
        self.secret_key = settings.PAYSTACK_SECRET_KEY
        self.public_key = settings.PAYSTACK_PUBLIC_KEY
        self.base_url = settings.PAYSTACK_BASE_URL

        self.headers = {
            'Authorization': f'Bearer {self.secret_key}',
            'Content-Type': 'application/json'
        }

    def initialize_payment(self, email, amount, reference, metadata=None, callback_url=None):
        """
        Initialize a payment transaction.

        Args:
            email: Customer email
            amount: Amount in kobo (multiply Naira by 100)
            reference: Unique transaction reference
            metadata: Optional metadata dict
            callback_url: Optional callback URL

        Returns:
            dict with authorization_url and access_code, or error
        """
        try:
            url = f'{self.base_url}/transaction/initialize'

            payload = {
                'email': email,
                'amount': int(amount * 100),  # Convert to kobo
                'reference': reference,
                'metadata': metadata or {},
                'callback_url': callback_url or settings.PAYSTACK_CALLBACK_URL
            }

            response = requests.post(url, json=payload, headers=self.headers, timeout=30)
            response.raise_for_status()

            data = response.json()

            if data['status']:
                return {
                    'success': True,
                    'authorization_url': data['data']['authorization_url'],
                    'access_code': data['data']['access_code'],
                    'reference': data['data']['reference']
                }
            else:
                return {
                    'success': False,
                    'error': data.get('message', 'Payment initialization failed')
                }

        except requests.RequestException as e:
            logger.error(f"Paystack API error (initialize): {str(e)}")
            return {
                'success': False,
                'error': str(e)
            }

    def verify_payment(self, reference):
        """
        Verify a payment transaction.

        Args:
            reference: Transaction reference

        Returns:
            dict with payment details or error
        """
        try:
            url = f'{self.base_url}/transaction/verify/{reference}'

            response = requests.get(url, headers=self.headers, timeout=30)
            response.raise_for_status()

            data = response.json()

            if data['status'] and data['data']['status'] == 'success':
                return {
                    'success': True,
                    'amount': Decimal(data['data']['amount']) / 100,  # Convert from kobo
                    'currency': data['data']['currency'],
                    'status': data['data']['status'],
                    'reference': data['data']['reference'],
                    'paid_at': data['data']['paid_at'],
                    'channel': data['data']['channel'],
                    'authorization': data['data'].get('authorization', {}),
                    'customer': data['data'].get('customer', {})
                }
            else:
                return {
                    'success': False,
                    'error': 'Payment verification failed or payment not successful'
                }

        except requests.RequestException as e:
            logger.error(f"Paystack API error (verify): {str(e)}")
            return {
                'success': False,
                'error': str(e)
            }

    def create_transfer_recipient(self, account_number, bank_code, account_name):
        """
        Create a transfer recipient.

        Args:
            account_number: Recipient bank account number
            bank_code: Recipient bank code
            account_name: Recipient account name

        Returns:
            dict with recipient_code or error
        """
        try:
            url = f'{self.base_url}/transferrecipient'

            payload = {
                'type': 'nuban',
                'name': account_name,
                'account_number': account_number,
                'bank_code': bank_code,
                'currency': 'NGN'
            }

            response = requests.post(url, json=payload, headers=self.headers, timeout=30)
            response.raise_for_status()

            data = response.json()

            if data['status']:
                return {
                    'success': True,
                    'recipient_code': data['data']['recipient_code'],
                    'details': data['data']
                }
            else:
                return {
                    'success': False,
                    'error': data.get('message', 'Failed to create transfer recipient')
                }

        except requests.RequestException as e:
            logger.error(f"Paystack API error (create recipient): {str(e)}")
            return {
                'success': False,
                'error': str(e)
            }

    def initiate_transfer(self, amount, recipient_code, reason, reference):
        """
        Initiate a transfer to a recipient.

        Args:
            amount: Amount in Naira
            recipient_code: Recipient code from create_transfer_recipient
            reason: Transfer reason/description
            reference: Unique transfer reference

        Returns:
            dict with transfer details or error
        """
        try:
            url = f'{self.base_url}/transfer'

            payload = {
                'source': 'balance',
                'amount': int(amount * 100),  # Convert to kobo
                'recipient': recipient_code,
                'reason': reason,
                'reference': reference
            }

            response = requests.post(url, json=payload, headers=self.headers, timeout=30)
            response.raise_for_status()

            data = response.json()

            if data['status']:
                return {
                    'success': True,
                    'transfer_code': data['data']['transfer_code'],
                    'status': data['data']['status'],
                    'reference': data['data']['reference'],
                    'details': data['data']
                }
            else:
                return {
                    'success': False,
                    'error': data.get('message', 'Transfer initiation failed')
                }

        except requests.RequestException as e:
            logger.error(f"Paystack API error (transfer): {str(e)}")
            return {
                'success': False,
                'error': str(e)
            }

    @staticmethod
    def verify_webhook_signature(payload, signature):
        """
        Verify Paystack webhook signature.

        Args:
            payload: Raw request body (bytes)
            signature: X-Paystack-Signature header value

        Returns:
            bool: True if signature is valid
        """
        try:
            secret = settings.PAYSTACK_WEBHOOK_SECRET.encode('utf-8')
            computed_signature = hmac.new(
                secret,
                payload,
                hashlib.sha512
            ).hexdigest()

            return hmac.compare_digest(computed_signature, signature)

        except Exception as e:
            logger.error(f"Webhook signature verification error: {str(e)}")
            return False
```

---

### Phase 2: Payment Endpoints

#### Step 2.1: Initialize Payment Endpoint

**File:** `apps/payments/views.py`

```python
from rest_framework import status
from rest_framework.decorators import api_view, permission_classes
from rest_framework.permissions import IsAuthenticated
from rest_framework.response import Response
from django.db import transaction
from django.shortcuts import get_object_or_404
from django.utils import timezone
from decimal import Decimal
import uuid
import logging

from apps.marketplace.models import MarketplaceListing
from apps.listings.models import Listing
from .models import Payment
from .paystack_client import PaystackClient
from utils.rate_limiter import rate_limit, user_key

logger = logging.getLogger(__name__)


@api_view(['POST'])
@permission_classes([IsAuthenticated])
@rate_limit(key_func=user_key('payment_init'), rate=10, per=3600)  # 10 payment inits per hour
def initialize_payment(request):
    """
    Initialize a payment for a marketplace listing.

    POST /api/v1/payments/initialize/

    Request:
    {
        "listing_id": "uuid",  # ID of the listing to purchase
        "amount": "255.00"      # Optional: verification amount (should match listing price)
    }

    Response:
    {
        "success": true,
        "message": "Payment initialized successfully",
        "payment_id": "uuid",
        "authorization_url": "https://checkout.paystack.com/xxxxx",
        "access_code": "xxxxx",
        "reference": "WW-xxxxx",
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

        # Ensure user is not the disposer (can't buy own listing)
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

        # If marketplace listing already exists, verify it's not already paid
        if not created:
            if marketplace_listing.escrow_status not in ['pending', 'failed']:
                return Response({
                    'success': False,
                    'message': f'Listing already has an active transaction (status: {marketplace_listing.escrow_status})'
                }, status=status.HTTP_400_BAD_REQUEST)

            # Update with current user if different
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
        with transaction.atomic():
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

            # Update marketplace listing status
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
```

#### Step 2.2: Verify Payment Endpoint

**File:** `apps/payments/views.py` (continued)

```python
@api_view(['GET'])
@permission_classes([IsAuthenticated])
def verify_payment(request):
    """
    Verify a payment after Paystack redirects back.

    GET /api/v1/payments/verify/?reference=WW-xxxxx

    Response:
    {
        "success": true,
        "message": "Payment verified successfully",
        "payment": {
            "payment_id": "uuid",
            "status": "success",
            "amount": "255.00",
            "reference": "WW-xxxxx",
            "paid_at": "2025-10-08T12:00:00Z"
        },
        "marketplace_listing": {
            "id": "uuid",
            "escrow_status": "locked"
        }
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
            # Update payment status to failed
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

        # Update payment record
        with transaction.atomic():
            payment.status = 'success'
            payment.is_verified = True
            payment.verified_at = timezone.now()
            payment.payment_method = result.get('channel', '')
            payment.paystack_response = result
            payment.save()

            # Lock escrow
            marketplace_listing = payment.marketplace_listing
            marketplace_listing.escrow_status = 'locked'
            marketplace_listing.payment_locked_at = timezone.now()
            marketplace_listing.save()

            # Update listing status
            listing = marketplace_listing.listing_id
            listing.status = 'accepted'
            listing.collector_id = user
            listing.save()

        # TODO: Send notification to disposer
        # notify_disposer_payment_received(marketplace_listing)

        logger.info(f"Payment verified: {payment.payment_id} for user {user.email}")

        return Response({
            'success': True,
            'message': 'Payment verified successfully. Escrow locked. Please contact the disposer to collect the item.',
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
```

---

## 📄 Document Status

**Current Status:** Phase 1 Complete - Architectural Analysis
**Next:** Continue with Phase 2 (Payment Endpoints) → Phase 3 (Webhooks) → Phase 4 (Payouts) → Phase 5 (Testing)

---

**Document will continue in next response...**
