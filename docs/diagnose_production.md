# Production Database Issue Diagnosis

## Summary
Production database is missing the `currency` column in the `wallets` table, causing 500 errors.

---

## Evidence from Render Logs
```
Error retrieving wallet for user: column wallets.currency does not exist
Error distributing referral reward: column wallets.currency does not exist
```

---

## Migration Timeline

### Migration 0001 (Sept 20, 2025)
**Initial wallet table creation**
- Created `wallets` table with: `wallet_id`, `balance`, `updated_at`, `user_id`
- Created `wallet_transactions` table

### Migration 0002 (Sept 24, 2025)
**Renamed foreign key field**
- Renamed `user_id` to `user` in Wallet model

### Migration 0003 (Sept 29, 2025) ⚠️ **THIS IS THE CRITICAL ONE**
**Added missing fields including `currency`**
- Added `currency` field (default='NGN')
- Added `created_at` field
- Added `is_active` field
- Added `points` field
- Added many WalletTransaction fields

---

## Current Situation

### Local Database (SQLite)
✅ **All migrations applied (including 0003)**
✅ **Currency column EXISTS**
✅ **All 8 columns present in wallets table**

### Production Database (PostgreSQL on Render)
❌ **Migration 0003 NOT applied**
❌ **Currency column MISSING**
❌ **Only 4 columns in wallets table** (wallet_id, balance, updated_at, user_id)
❌ **Also missing: created_at, is_active, points**

---

## Why This Happened

**Most likely scenario:**
1. Production was deployed with migrations 0001 and 0002 applied
2. Migration 0003 was created on **Sept 29** but never deployed/applied to production
3. The codebase now expects the `currency` field (and others) but production DB doesn't have it

**Possible causes:**
- Migration 0003 wasn't committed when production was last deployed
- Migration command wasn't run during deployment
- Manual database changes bypassed migrations
- Deployment script doesn't include `python manage.py migrate`

---

## Verification Steps

### Step 1: Check Production Migration Status

**Run on Render Shell:**
```bash
python manage.py showmigrations wallet
```

**Expected output if 0003 is missing:**
```
wallet
 [X] 0001_initial
 [X] 0002_rename_user_id_wallet_user_and_more
 [ ] 0003_alter_wallettransaction_options_wallet_created_at_and_more
```

### Step 2: Check Actual Database Schema

**Run on Render Shell:**
```bash
python check_production_schema.py
```

This will show exactly which columns exist in production.

---

## The Fix

### Option 1: Apply Missing Migration (RECOMMENDED)

**Run on Render Shell:**
```bash
python manage.py migrate wallet
```

This will apply migration 0003, adding the missing columns.

**Why this is safe:**
- Migration adds columns with default values (currency='NGN', is_active=True, points=0)
- No data loss
- Existing records will automatically get the new columns
- Takes ~1 second

### Option 2: Update Render Start Command (PERMANENT FIX)

**Current start command:**
```bash
python manage.py runserver 0.0.0.0:$PORT
```

**Change to:**
```bash
python manage.py migrate --no-input && python manage.py runserver 0.0.0.0:$PORT
```

**Benefits:**
- Migrations run automatically on every deployment
- Prevents this issue from happening again
- Standard Django deployment practice

---

## Post-Fix Verification

### 1. Check Wallet Balance Endpoint
```bash
curl https://wasteworth-backend-django.onrender.com/api/v1/wallet/balance/ \
  -H "Authorization: Bearer <token>"
```

**Expected:** 200 OK (not 500)

### 2. Test Referral Rewards
- Create a user with referral code
- Check referrer's wallet has 100 points

### 3. Re-run E2E Test
```bash
python e2e_test_with_otp.py
```

**Expected:** All wallet-related tests pass

---

## Impact of NOT Fixing

**Current broken functionality:**
- ❌ Wallet balance retrieval (500 errors)
- ❌ Referral rewards not being distributed
- ❌ Transaction history not working properly
- ❌ Activity rewards cannot be credited
- ❌ Point redemptions impossible
- ❌ Users losing trust in the system

**Financial impact:**
- Referrers not receiving their 100 points per referral
- Users not earning activity rewards
- Potential revenue loss from rewards program

---

## Root Cause Analysis

**Why wasn't this caught earlier?**
1. Local testing worked (migrations applied locally)
2. Production deployment didn't include migration step
3. No automated checks for migration status
4. No staging environment to catch this

**Prevention for future:**
1. ✅ Add migrations to deployment command
2. ✅ Add health check endpoint that verifies migrations
3. ✅ Set up staging environment
4. ✅ Add CI/CD checks for pending migrations
5. ✅ Monitor error logs more frequently

---

## Questions to Answer

1. **When was production last deployed?**
   - Check if it was before Sept 29 (when 0003 was created)

2. **What's in the production migration history?**
   - Run: `python manage.py showmigrations` on Render

3. **Is there a deployment pipeline?**
   - Does it include `python manage.py migrate`?

4. **Any manual database changes?**
   - Check if anyone ran SQL directly on production

---

## Next Steps

**Immediate (NOW):**
1. Run `python check_production_schema.py` on Render to confirm diagnosis
2. Run `python manage.py migrate wallet` on Render to fix the issue
3. Test wallet endpoints to verify fix

**Short-term (TODAY):**
1. Update Render start command to include migrations
2. Re-run E2E test to verify everything works
3. Check if any users are missing referral rewards (backfill if needed)

**Long-term (THIS WEEK):**
1. Set up staging environment
2. Add migration checks to CI/CD
3. Document deployment process
4. Add monitoring/alerting for 500 errors

---

## Contact

If you need help running these commands on Render:
1. Go to Render Dashboard
2. Select your Django service
3. Click "Shell" tab
4. Run the verification and fix commands

---

**Created:** October 1, 2025
**Status:** Awaiting production verification and fix
