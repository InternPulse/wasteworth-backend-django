# 🚀 Payment System - Quick Start Guide

**Get up and running in 5 minutes!**

---

## ✅ Implementation Status

**Status:** ✅ COMPLETE - Ready for testing

**What's Built:**
- 2 new database tables (payments, payouts)
- 5 API endpoints for complete payment flow
- Automatic reward distribution
- Automatic payout processing
- Admin panel integration

---

## 📋 Before You Start

Add these to your `.env` file:

```env
# Get from https://dashboard.paystack.com
PAYSTACK_SECRET_KEY=sk_test_your_key_here
PAYSTACK_PUBLIC_KEY=pk_test_your_key_here
PAYSTACK_CALLBACK_URL=https://yourfrontend.com/payment/callback
PAYSTACK_WEBHOOK_SECRET=whsec_your_secret_here
```

---

## 🔗 API Endpoints

### Base URL: `/api/v1/payments/`

| Endpoint | Method | Who Uses | Purpose |
|----------|--------|----------|---------|
| `/initialize/` | POST | Recycler | Start payment |
| `/verify/` | GET | Recycler | Confirm payment |
| `/confirm-release/` | POST | Disposer | Item given |
| `/confirm-receipt/` | POST | Recycler | Item received (triggers rewards) |
| `/webhook/` | POST | Paystack | Internal only |

---

## 🎬 Usage Flow

### **Step 1: Recycler Initiates Payment**

```bash
POST /api/v1/payments/initialize/
Authorization: Bearer {recycler_token}

{
  "listing_id": "abc-123",
  "amount": "255.00"
}

→ Returns Paystack checkout URL
→ Redirect recycler to URL to pay
```

### **Step 2: Recycler Completes Payment**

```bash
# After payment on Paystack, redirect back with reference

GET /api/v1/payments/verify/?reference=WW-XXXXXXXXXXXX
Authorization: Bearer {recycler_token}

→ Escrow locked
→ Returns disposer contact info
```

### **Step 3: Disposer Confirms Release**

```bash
# Disposer gives item to recycler

POST /api/v1/payments/confirm-release/
Authorization: Bearer {disposer_token}

{
  "marketplace_listing_id": "def-456"
}

→ Waiting for recycler confirmation
```

### **Step 4: Recycler Confirms Receipt** ⭐

```bash
# Recycler received the item

POST /api/v1/payments/confirm-receipt/
Authorization: Bearer {recycler_token}

{
  "marketplace_listing_id": "def-456"
}

→ 🎉 TRIGGERS EVERYTHING:
   ✅ Rewards distributed (255 points each)
   ✅ Payout to disposer (₦242.25 to wallet)
   ✅ Escrow released
   ✅ Transaction complete
```

---

## 🧪 Test with Postman

### **1. Initialize Payment**
```
POST http://localhost:8000/api/v1/payments/initialize/
Headers:
  Authorization: Bearer {token}
  Content-Type: application/json
Body:
{
  "listing_id": "your-listing-uuid"
}
```

### **2. Paystack Test Cards**
- **Success:** `5531886652142950` (Mastercard)
- **Success:** `4084084084084081` (Visa)
- **CVV:** Any 3 digits
- **Expiry:** Any future date
- **PIN:** 3310

### **3. Verify Payment**
```
GET http://localhost:8000/api/v1/payments/verify/?reference=WW-XXXXXXXXXXXX
Headers:
  Authorization: Bearer {token}
```

---

## 📊 Check Results

### **Admin Panel**
```
http://localhost:8000/admin/payments/payment/
http://localhost:8000/admin/payments/payout/
```

### **Wallet Balance**
```
GET http://localhost:8000/api/v1/wallet/
Authorization: Bearer {token}

→ Check balance and points updated
```

### **Transaction History**
```
GET http://localhost:8000/api/v1/wallet/transactions/
Authorization: Bearer {token}

→ See reward and payout transactions
```

---

## 🎯 Expected Results

**For 25.5kg plastic listing at ₦255:**

**Disposer Receives:**
- ₦242.25 in wallet (₦255 - 5% fee)
- 255 points (25.5kg × 10 points/kg)

**Recycler Receives:**
- 255 points (25.5kg × 10 points/kg)

**Platform Earns:**
- ₦12.75 (5% of ₦255)

**If Referred:**
- Referrer gets BONUS 100 points (if first transaction)

---

## 🔍 Troubleshooting

### Payment initialization fails
- Check Paystack keys in `.env`
- Verify user role (must be recycler, not disposer)
- Check listing exists and is available

### Verification fails
- Check reference is correct
- Verify payment was completed on Paystack
- Check webhook secret is configured

### Rewards not distributed
- Ensure confirm_item_received was called
- Check `escrow_status = 'released'`
- View logs for errors

### Payout not working
- Check disposer wallet exists
- Verify platform fee calculation
- Check payout record in admin

---

## 📝 Database Query Examples

```python
# Check payment status
from apps.payments.models import Payment
Payment.objects.filter(payer__email='recycler@test.com')

# Check payout status
from apps.payments.models import Payout
Payout.objects.filter(recipient__email='disposer@test.com')

# Check escrow status
from apps.marketplace.models import MarketplaceListing
MarketplaceListing.objects.filter(escrow_status='released')

# Check wallet balances
from apps.wallet.models import Wallet
Wallet.objects.get(user__email='disposer@test.com')
```

---

## ⚡ Quick Commands

```bash
# Start server
python manage.py runserver

# Check configuration
python manage.py check

# View migrations
python manage.py showmigrations payments marketplace

# Create admin user (if needed)
python manage.py createsuperuser

# Run schema verification
python verify_schema.py
```

---

## 📚 Documentation

- **Complete Guide:** [PAYMENT_IMPLEMENTATION_COMPLETE.md](PAYMENT_IMPLEMENTATION_COMPLETE.md)
- **Architecture:** [ESCROW_PAYMENT_ARCHITECTURE_REVIEW.md](ESCROW_PAYMENT_ARCHITECTURE_REVIEW.md)
- **Database:** [NEW_SCHEMA_EXPLAINED.md](NEW_SCHEMA_EXPLAINED.md)

---

## 🎉 You're Ready!

Everything is set up and ready to test. Just add your Paystack keys and start testing the payment flow!

**Questions?** Check the full documentation or Paystack docs at https://paystack.com/docs
