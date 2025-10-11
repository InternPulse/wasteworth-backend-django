# 🚨 CRITICAL: Database Migration Required

## Issue Discovered During E2E Testing

**Date:** October 1, 2025
**Severity:** CRITICAL
**Impact:** All wallet operations failing, referral rewards not being distributed

---

## Problem

The production database is **missing the `currency` column** in the `wallets` table.

### Error from Render Logs:
```
Error retrieving wallet for user test_20251001105054_rbpe@wasteworth.test:
column wallets.currency does not exist
LINE 1: ...et_id", "wallets"."user_id", "wallets"."balance", "wallets"....

Error distributing referral reward to test_20251001105054_rbpe@wasteworth.test:
column wallets.currency does not exist
```

### Affected Operations:
1. ❌ **Wallet balance retrieval** - Returns 500 error
2. ❌ **Referral rewards** - Fail silently when user signs up with referral code
3. ❌ **Activity rewards** - Cannot be distributed
4. ❌ **Transaction history** - Cannot be retrieved properly

---

## Root Cause

Database migrations have not been applied to production. The `Wallet` model defines a `currency` field:

**File:** `apps/wallet/models.py:13`
```python
class Wallet(models.Model):
    # ...
    currency = models.CharField(max_length=3, default='NGN', help_text="Currency code (NGN, GHS, etc.)")
```

But the database table doesn't have this column.

---

## Immediate Fix

### Step 1: Check Migration Status
```bash
python manage.py showmigrations wallet
```

### Step 2: Create Migration (if missing)
```bash
python manage.py makemigrations wallet
```

### Step 3: Apply Migrations
```bash
python manage.py migrate wallet
```

### Step 4: For Render Deployment

**Option A: Run manual migration**
1. Go to Render Dashboard
2. Navigate to your Django service
3. Open Shell tab
4. Run: `python manage.py migrate`

**Option B: Update deployment command**
```bash
# In Render settings, change Start Command to:
python manage.py migrate --no-input && python manage.py runserver 0.0.0.0:$PORT
```

This ensures migrations run automatically on each deployment.

---

## Verification

After applying the migration, test with:

```python
# In Django shell
from apps.wallet.models import Wallet
from django.contrib.auth import get_user_model

User = get_user_model()
user = User.objects.first()

# Try creating a wallet
wallet, created = Wallet.objects.get_or_create(
    user=user,
    defaults={
        'balance': 0.00,
        'currency': 'NGN',
        'points': 0,
        'is_active': True
    }
)

print(f"✓ Wallet created: {created}")
print(f"✓ Currency: {wallet.currency}")
print(f"✓ Points: {wallet.points}")
```

Expected output:
```
✓ Wallet created: True
✓ Currency: NGN
✓ Points: 0
```

---

## Test Cases to Re-run After Fix

1. **Referral Reward Test:**
   - Create recycler account
   - Create disposer account with recycler's referral code
   - Check recycler wallet - should have 100 points

2. **Wallet Balance Test:**
   - Login as any user
   - GET `/api/v1/wallet/balance/`
   - Should return 200 with wallet data

3. **Full E2E Test:**
   - Run: `python e2e_test.py`
   - Should pass wallet-related tests

---

## Impact on Existing Users

**WARNING:** If users have already been created:

1. **Existing referrals may have failed** - Referrers did not receive their 100 points
2. **Wallets may not exist** - Wallet creation failed during signup
3. **Need to backfill rewards** - Consider script to credit missed referral rewards

### Backfill Script (Optional):
```python
from apps.referral.models import Referral
from apps.wallet.utils import distribute_referral_reward

# Find all referrals where reward failed
failed_referrals = Referral.objects.filter(status='pending')

for referral in failed_referrals:
    try:
        distribute_referral_reward(
            referrer_user=referral.referrer,
            referee_user=referral.referee,
            referral_obj=referral,
            is_signup=True
        )
        print(f"✓ Credited {referral.referrer.email}")
    except Exception as e:
        print(f"✗ Failed for {referral.referrer.email}: {e}")
```

---

## Prevention for Future

### Add to CI/CD Pipeline:
```yaml
# Example GitHub Actions
- name: Check for pending migrations
  run: |
    python manage.py makemigrations --check --dry-run

- name: Run migrations
  run: |
    python manage.py migrate --no-input
```

### Add to Render Build Command:
```bash
python manage.py migrate --no-input
```

### Monitor Migration Status:
```python
# Add to health check endpoint
from django.db.migrations.executor import MigrationExecutor
from django.db import connections

def check_migrations():
    connection = connections['default']
    executor = MigrationExecutor(connection)
    targets = executor.loader.graph.leaf_nodes()
    plan = executor.migration_plan(targets)

    if plan:
        return {"status": "error", "pending_migrations": len(plan)}
    return {"status": "ok"}
```

---

## Related Files

- **Model:** `apps/wallet/models.py:6-21`
- **Wallet Views:** `apps/wallet/views.py:59-92`
- **Reward Utils:** `apps/wallet/utils.py:69-133`
- **User Signup:** `apps/users/serializers.py:61-104`
- **E2E Test:** `e2e_test.py`
- **Full Report:** `E2E_TEST_REPORT.md`

---

## Status

- [ ] Migration created
- [ ] Migration applied locally
- [ ] Migration applied to production (Render)
- [ ] Wallet balance endpoint tested
- [ ] Referral reward tested
- [ ] E2E test re-run
- [ ] Existing users backfilled (if needed)

---

**Priority:** CRITICAL - Fix immediately
**Estimated Time:** 5-10 minutes
**Risk:** Low (just adding missing column)

**Contact:** See test logs in `E2E_TEST_REPORT.md` for full details
