# 📊 New Database Schema - Complete Explanation

**Date:** October 8, 2025
**Purpose:** Explain all new tables and fields added for escrow payment system

---

## 🎯 High-Level Overview

We added **2 new tables** and **7 new fields** to enable a complete escrow payment flow using Paystack. Here's why each exists:

---

## 📋 Table 1: `payments` (New Table)

**Purpose:** Track every payment transaction made by recyclers through Paystack.

### Why This Table Exists:

When a **Recycler** wants to buy waste from a **Disposer**, they need to pay. This table records:
- Who paid
- How much they paid
- When they paid
- Payment status (pending, success, failed)
- Paystack transaction details

### Real-World Example:

```
Recycler "John" wants to buy 25.5kg plastic from Disposer "Mary" for ₦255.

1. System creates Payment record with:
   - Payer: John
   - Amount: ₦255
   - Status: pending
   - Paystack reference: WW-ABC123

2. John completes payment on Paystack

3. System updates Payment record:
   - Status: success
   - Verified: true
   - Payment method: card

Now we have a permanent record that John paid ₦255.
```

### Fields Breakdown:

| Field Name | Type | Purpose | Example |
|------------|------|---------|---------|
| **payment_id** | UUID | Unique ID for this payment | `a1b2c3d4-...` |
| **marketplace_listing** | ForeignKey | Which listing is being paid for | Links to MarketplaceListing |
| **payer** | ForeignKey | Who is paying (recycler) | John (User) |
| **amount** | Decimal | How much in Naira | `255.00` |
| **currency** | CharField | Currency code | `NGN` |
| **payment_method** | CharField | How they paid | `card`, `bank`, `ussd` |
| **paystack_reference** | CharField | Unique Paystack transaction ID | `WW-ABC123` |
| **paystack_access_code** | CharField | Paystack checkout code | `xyz789` |
| **paystack_authorization_url** | URLField | Checkout page URL | `https://checkout.paystack.com/...` |
| **status** | CharField | Payment status | `pending`, `success`, `failed` |
| **payment_provider** | CharField | Which gateway used | `paystack` |
| **is_verified** | Boolean | Did we confirm payment? | `True`/`False` |
| **verified_at** | DateTime | When was it verified | `2025-10-08 14:30:00` |
| **paystack_response** | JSONField | Full response from Paystack | `{...}` |
| **webhook_received_at** | DateTime | When Paystack notified us | `2025-10-08 14:30:05` |
| **retry_count** | Integer | How many times we retried | `0` |
| **last_error** | TextField | Error message if failed | `Card declined` |
| **created_at** | DateTime | When payment initiated | `2025-10-08 14:25:00` |
| **updated_at** | DateTime | Last update time | `2025-10-08 14:30:00` |

### Key Relationships:

```
Payment ←→ MarketplaceListing (OneToOne)
   ↓
Payment → User (payer = recycler)
```

**One-to-One with MarketplaceListing means:**
- Each marketplace transaction has exactly ONE payment
- Each payment belongs to exactly ONE marketplace transaction

---

## 📋 Table 2: `payouts` (New Table)

**Purpose:** Track money transfers from the platform to disposers (sellers).

### Why This Table Exists:

After a transaction completes successfully:
1. Recycler paid ₦255 (tracked in `payments` table)
2. Item was collected
3. Both parties confirmed
4. Now **Disposer needs to receive their money**

This table tracks:
- Who receives the payout (disposer)
- How much they receive (minus platform fee)
- Bank account details
- Payout status

### Real-World Example:

```
Transaction completed:
- Recycler John paid ₦255 (in payments table)
- Platform takes 5% fee = ₦12.75
- Disposer Mary should receive = ₦242.25

System creates Payout record:
- Recipient: Mary
- Gross amount: ₦255.00
- Platform fee: ₦12.75
- Net amount: ₦242.25
- Status: pending

System sends ₦242.25 to Mary's bank account via Paystack Transfer API

System updates Payout record:
- Status: success
- Completed: true
- Paystack transfer code: TRF_xyz123

Mary receives money in her bank account.
```

### Fields Breakdown:

| Field Name | Type | Purpose | Example |
|------------|------|---------|---------|
| **payout_id** | UUID | Unique ID for this payout | `e5f6g7h8-...` |
| **payment** | ForeignKey | Which payment this payout is for | Links to Payment |
| **recipient** | ForeignKey | Who receives money (disposer) | Mary (User) |
| **recipient_account_number** | CharField | Bank account number | `0123456789` |
| **recipient_bank_code** | CharField | Bank code | `058` (GTBank) |
| **recipient_account_name** | CharField | Account name | `Mary Johnson` |
| **amount** | Decimal | Original payment amount | `255.00` |
| **platform_fee** | Decimal | Platform commission (5%) | `12.75` |
| **net_amount** | Decimal | What disposer actually gets | `242.25` |
| **currency** | CharField | Currency code | `NGN` |
| **paystack_transfer_code** | CharField | Paystack transfer ID | `TRF_xyz123` |
| **paystack_transfer_id** | CharField | Additional Paystack ID | `12345` |
| **status** | CharField | Payout status | `pending`, `success`, `failed` |
| **is_completed** | Boolean | Did payout succeed? | `True`/`False` |
| **completed_at** | DateTime | When money was sent | `2025-10-08 15:00:00` |
| **paystack_response** | JSONField | Full response from Paystack | `{...}` |
| **retry_count** | Integer | How many times we retried | `0` |
| **last_error** | TextField | Error message if failed | `Invalid account` |
| **created_at** | DateTime | When payout initiated | `2025-10-08 14:45:00` |
| **updated_at** | DateTime | Last update time | `2025-10-08 15:00:00` |

### Key Relationships:

```
Payout ←→ Payment (OneToOne)
   ↓
Payout → User (recipient = disposer)
```

**One-to-One with Payment means:**
- Each payment has exactly ONE payout (when transaction completes)
- Each payout belongs to exactly ONE payment

---

## 📋 Updated Table: `marketplace_listings` (7 New Fields)

**Purpose:** Enhanced tracking of the escrow payment lifecycle.

### Why These Fields Exist:

The **old** `marketplace_listings` table only had:
- `escrow_status` (4 values: pending, locked, released, cancelled)

But this wasn't enough to track a complete payment flow. We needed to know:
- **When** did each status change happen?
- **Who** confirmed what?
- What's the **complete timeline** of the transaction?

### New Fields Breakdown:

#### **Group 1: Timestamp Tracking (5 fields)**

These track **when** each major event happened:

| Field Name | Type | Purpose | When It Gets Set | Example |
|------------|------|---------|------------------|---------|
| **payment_initiated_at** | DateTime | When recycler started paying | Recycler clicks "Pay Now" | `2025-10-08 14:25:00` |
| **payment_locked_at** | DateTime | When payment was confirmed | Paystack confirms payment | `2025-10-08 14:30:00` |
| **item_released_at** | DateTime | When disposer gave item to recycler | Disposer clicks "Item Released" | `2025-10-08 15:00:00` |
| **confirmed_at** | DateTime | When recycler confirmed receipt | Recycler clicks "Confirm Receipt" | `2025-10-08 16:00:00` |
| **released_at** | DateTime | When escrow was fully released | System processes payout + rewards | `2025-10-08 16:01:00` |

**Why timestamps matter:**

1. **Audit Trail:** See exactly when everything happened
2. **Dispute Resolution:** "Disposer said they released on Monday, but timestamp shows Wednesday"
3. **Analytics:** "Average time from payment to confirmation is 3 hours"
4. **Timeout Detection:** "It's been 48 hours since payment, still not released"

#### **Group 2: Confirmation Flags (2 fields)**

These track **who** confirmed what:

| Field Name | Type | Purpose | Example |
|------------|------|---------|---------|
| **disposer_confirmed** | Boolean | Did disposer confirm item release? | `True` = Yes, I gave the item |
| **recycler_confirmed** | Boolean | Did recycler confirm receipt? | `True` = Yes, I received the item |

**Why these matter:**

Both parties need to confirm for escrow to release:

```
✅ Disposer confirms: "I gave the item to recycler"
❌ Recycler has NOT confirmed yet
→ Escrow status = "item_released" (waiting for recycler)

✅ Disposer confirms: "I gave the item to recycler"
✅ Recycler confirms: "I received the item"
→ Escrow status = "confirmed" → triggers payout + rewards
```

**Prevents fraud:**
- Disposer can't claim they released item if `disposer_confirmed = False`
- Recycler can't get refund after receiving item if `recycler_confirmed = True`

---

## 🔄 How Everything Works Together

### Complete Transaction Flow:

```
┌─────────────────────────────────────────────────────────────────┐
│                  STEP 1: PAYMENT INITIATED                       │
└─────────────────────────────────────────────────────────────────┘

Recycler clicks "Buy" on listing

✅ Creates Payment record:
   - payer = John (recycler)
   - amount = ₦255
   - status = pending
   - paystack_reference = WW-ABC123

✅ Updates MarketplaceListing:
   - escrow_status = "payment_initiated"
   - payment_initiated_at = NOW

Returns Paystack checkout URL to user


┌─────────────────────────────────────────────────────────────────┐
│                  STEP 2: PAYMENT COMPLETED                       │
└─────────────────────────────────────────────────────────────────┘

Recycler pays on Paystack
Paystack sends webhook to our server

✅ Updates Payment record:
   - status = success
   - is_verified = True
   - verified_at = NOW
   - payment_method = "card"

✅ Updates MarketplaceListing:
   - escrow_status = "locked"
   - payment_locked_at = NOW

✅ Updates Listing:
   - status = "accepted"
   - collector_id = John (recycler)

Sends notification to Disposer: "Payment received! Please release item."


┌─────────────────────────────────────────────────────────────────┐
│                  STEP 3: ITEM RELEASED                           │
└─────────────────────────────────────────────────────────────────┘

Disposer gives item to Recycler
Disposer clicks "Item Released" button

✅ Updates MarketplaceListing:
   - escrow_status = "item_released"
   - item_released_at = NOW
   - disposer_confirmed = True

Sends notification to Recycler: "Confirm receipt to release escrow"


┌─────────────────────────────────────────────────────────────────┐
│                  STEP 4: RECEIPT CONFIRMED                       │
└─────────────────────────────────────────────────────────────────┘

Recycler receives item
Recycler clicks "Confirm Receipt" button

✅ Updates MarketplaceListing:
   - escrow_status = "confirmed"
   - confirmed_at = NOW
   - recycler_confirmed = True

✅ Updates Listing:
   - status = "completed"


┌─────────────────────────────────────────────────────────────────┐
│                  STEP 5: ESCROW RELEASED                         │
└─────────────────────────────────────────────────────────────────┘

System automatically triggers:

1️⃣ REWARD DISTRIBUTION (apps/wallet/utils.py)
   ✅ Disposer gets 255 points (25.5kg × 10 points/kg)
   ✅ Recycler gets 255 points (25.5kg × 10 points/kg)
   ✅ Referral bonuses (if applicable)

2️⃣ PAYOUT PROCESSING (apps/payments/utils.py)
   ✅ Creates Payout record:
      - recipient = Mary (disposer)
      - amount = ₦255.00
      - platform_fee = ₦12.75 (5%)
      - net_amount = ₦242.25
      - status = pending

   ✅ Sends money via Paystack Transfer API
      - To Mary's bank account
      - Amount: ₦242.25

   ✅ Updates Payout record:
      - status = success
      - is_completed = True
      - completed_at = NOW

3️⃣ FINAL STATUS UPDATE
   ✅ Updates MarketplaceListing:
      - escrow_status = "released"
      - released_at = NOW

Transaction complete! 🎉
```

---

## 📊 Database Relationships Diagram

```
┌─────────────┐
│    User     │
└──────┬──────┘
       │
       ├─────────────────┐
       │                 │
       │ (as disposer)   │ (as recycler)
       ↓                 ↓
┌─────────────┐    ┌──────────────┐
│   Listing   │←───│MarketplaceListing│
└─────────────┘    └──────┬───────┘
                          │
                          │ OneToOne
                          ↓
                   ┌──────────────┐
                   │   Payment    │←── (payer = recycler)
                   └──────┬───────┘
                          │ OneToOne
                          ↓
                   ┌──────────────┐
                   │    Payout    │←── (recipient = disposer)
                   └──────────────┘
```

**Flow:**
1. **User (Disposer)** creates **Listing**
2. **User (Recycler)** wants to buy → creates **MarketplaceListing**
3. **Recycler** pays → creates **Payment** (linked to MarketplaceListing)
4. Transaction completes → creates **Payout** (linked to Payment)
5. **Disposer** receives money

---

## 🎯 Why This Design?

### **Separation of Concerns:**

| Table | Responsibility |
|-------|----------------|
| **Payment** | Track money coming IN (from recycler) |
| **Payout** | Track money going OUT (to disposer) |
| **MarketplaceListing** | Track escrow state and confirmations |

### **Auditability:**

Every financial transaction has:
- Unique ID
- Timestamps
- Status history
- Full Paystack response (in JSON)
- Error logs (if any)

### **Flexibility:**

- Can handle refunds (Payment status = refunded)
- Can handle failed payouts (retry logic)
- Can track partial payments (future feature)
- Can support multiple payment providers (not just Paystack)

---

## 📝 Summary Table

| Component | Purpose | Key Benefit |
|-----------|---------|-------------|
| **`payments` table** | Track incoming payments from recyclers | Know who paid, how much, when, and status |
| **`payouts` table** | Track outgoing payments to disposers | Know who was paid, how much, when, and status |
| **Timestamp fields** | Record when each event happened | Complete audit trail for disputes |
| **Confirmation flags** | Track who confirmed what | Prevent fraud, ensure both parties agree |
| **Escrow status** | Track overall transaction state | Know exactly where transaction is in lifecycle |

---

## ✅ What You Can Do Now

With these new tables and fields, you can:

1. ✅ **Accept payments via Paystack**
   - Recyclers can pay securely
   - Funds held in escrow

2. ✅ **Track payment status**
   - See all payments in admin panel
   - Filter by status, date, user

3. ✅ **Manage escrow lifecycle**
   - Lock funds when payment succeeds
   - Release when both parties confirm

4. ✅ **Automate payouts**
   - Send money to disposers automatically
   - Track payout status

5. ✅ **Distribute rewards**
   - Award points when transaction completes
   - Link rewards to specific payments

6. ✅ **Handle disputes**
   - See complete timeline
   - Check who confirmed what
   - Verify payment amounts

7. ✅ **Generate reports**
   - Total payments received
   - Total payouts sent
   - Platform fees collected
   - Transaction completion rate

---

## 🚀 Next Steps

Now that the database is ready, you can:

1. **Implement Paystack API client** (utility to talk to Paystack)
2. **Create payment endpoints** (initialize, verify, webhook)
3. **Create confirmation endpoints** (item released, item received)
4. **Test the full flow** (end-to-end payment)
5. **Deploy to production** (real money!)

---

**Ready to proceed?** All the groundwork is done! 🎉
