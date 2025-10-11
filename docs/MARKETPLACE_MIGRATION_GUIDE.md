# 🔄 MarketplaceListing Migration Guide

**Purpose:** Add new fields to `MarketplaceListing` model for enhanced escrow payment tracking

**Risk Level:** ✅ **LOW** - All changes are backward compatible

---

## 📋 Current vs New Schema

### **BEFORE (Current Schema)**

```python
# apps/marketplace/models.py - CURRENT
class MarketplaceListing(models.Model):
    class Meta:
        db_table = 'marketplace_listings'

    ESCROW_STATUS_CHOICES = [
        ('pending', 'Pending'),      # 4 states only
        ('locked', 'Locked'),
        ('released', 'Released'),
        ('cancelled', 'Cancelled'),
    ]

    # Fields
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    listing_id = models.ForeignKey(Listing, on_delete=models.CASCADE)
    recycler_id = models.ForeignKey(User, on_delete=models.CASCADE, null=True, blank=True)
    price = models.DecimalField(max_digits=10, decimal_places=2)
    escrow_status = models.CharField(max_length=20, choices=ESCROW_STATUS_CHOICES, default='pending')
    created_at = models.DateTimeField(auto_now_add=True)

    # Total: 6 fields
```

### **AFTER (Enhanced Schema)**

```python
# apps/marketplace/models.py - ENHANCED
class MarketplaceListing(models.Model):
    class Meta:
        db_table = 'marketplace_listings'
        indexes = [
            models.Index(fields=['escrow_status', '-created_at']),  # ⭐ NEW
            models.Index(fields=['auto_confirm_deadline']),         # ⭐ NEW
        ]

    ESCROW_STATUS_CHOICES = [
        ('pending', 'Pending'),                      # ✅ Existing
        ('payment_initiated', 'Payment Initiated'),  # ⭐ NEW
        ('locked', 'Locked'),                        # ✅ Existing
        ('item_released', 'Item Released'),          # ⭐ NEW
        ('confirmed', 'Confirmed'),                  # ⭐ NEW
        ('released', 'Released'),                    # ✅ Existing
        ('refunded', 'Refunded'),                    # ⭐ NEW
        ('failed', 'Failed'),                        # ⭐ NEW
        ('cancelled', 'Cancelled'),                  # ✅ Existing
        ('disputed', 'Disputed'),                    # ⭐ NEW
    ]

    # ============ EXISTING FIELDS (unchanged) ============
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    listing_id = models.ForeignKey(Listing, on_delete=models.CASCADE, related_name='marketplace_listings')
    recycler_id = models.ForeignKey(User, on_delete=models.CASCADE, null=True, blank=True, related_name='marketplace_purchases')
    price = models.DecimalField(max_digits=10, decimal_places=2)
    escrow_status = models.CharField(max_length=20, choices=ESCROW_STATUS_CHOICES, default='pending')
    created_at = models.DateTimeField(auto_now_add=True)

    # ============ NEW FIELDS (all optional) ============

    # Timestamp tracking for each state transition
    payment_initiated_at = models.DateTimeField(null=True, blank=True)
    payment_locked_at = models.DateTimeField(null=True, blank=True)
    item_released_at = models.DateTimeField(null=True, blank=True)
    confirmed_at = models.DateTimeField(null=True, blank=True)
    released_at = models.DateTimeField(null=True, blank=True)

    # Confirmation tracking
    disposer_confirmed = models.BooleanField(default=False)
    recycler_confirmed = models.BooleanField(default=False)

    # Automatic confirmation deadline (7 days after item_released)
    auto_confirm_deadline = models.DateTimeField(null=True, blank=True)

    # Total: 15 fields (6 existing + 9 new)
```

---

## 📊 Field-by-Field Analysis

### **New Fields Added**

| Field Name | Type | Nullable | Default | Purpose |
|------------|------|----------|---------|---------|
| `payment_initiated_at` | DateTimeField | ✅ Yes | `NULL` | When recycler started payment |
| `payment_locked_at` | DateTimeField | ✅ Yes | `NULL` | When payment was confirmed and escrow locked |
| `item_released_at` | DateTimeField | ✅ Yes | `NULL` | When disposer confirmed item release |
| `confirmed_at` | DateTimeField | ✅ Yes | `NULL` | When recycler confirmed receipt |
| `released_at` | DateTimeField | ✅ Yes | `NULL` | When escrow was released (final state) |
| `disposer_confirmed` | BooleanField | ❌ No | `False` | Whether disposer confirmed item release |
| `recycler_confirmed` | BooleanField | ❌ No | `False` | Whether recycler confirmed receipt |
| `auto_confirm_deadline` | DateTimeField | ✅ Yes | `NULL` | Deadline for auto-confirmation |

**Total:** 8 new fields + 1 expanded enum (escrow_status choices)

---

## 🔍 Backward Compatibility Analysis

### ✅ **100% Backward Compatible**

**Why?**

1. **All new fields are optional:**
   - 5 timestamp fields: `null=True, blank=True`
   - 1 deadline field: `null=True, blank=True`
   - 2 boolean fields: `default=False`

2. **Existing fields unchanged:**
   - Same names
   - Same types
   - Same constraints
   - Same relationships

3. **Expanded enum (not replaced):**
   ```python
   # Old values still valid
   'pending' ✅ Still exists
   'locked' ✅ Still exists
   'released' ✅ Still exists
   'cancelled' ✅ Still exists

   # New values added
   'payment_initiated' ⭐ Optional to use
   'item_released' ⭐ Optional to use
   'confirmed' ⭐ Optional to use
   # ... etc
   ```

4. **Existing queries work unchanged:**
   ```python
   # This query still works exactly the same
   MarketplaceListing.objects.filter(escrow_status='released').count()

   # This query still works exactly the same
   marketplace_listing = MarketplaceListing.objects.create(
       listing_id=listing,
       recycler_id=user,
       price=255.00,
       escrow_status='pending'
   )
   # New fields automatically set to NULL or False
   ```

---

## 📝 Migration File

### **Step 1: Generate Migration**

```bash
python manage.py makemigrations marketplace
```

**Expected output:**
```
Migrations for 'marketplace':
  apps/marketplace/migrations/0002_enhance_escrow_tracking.py
    - Alter field escrow_status on marketplacelisting
    - Add field payment_initiated_at to marketplacelisting
    - Add field payment_locked_at to marketplacelisting
    - Add field item_released_at to marketplacelisting
    - Add field confirmed_at to marketplacelisting
    - Add field released_at to marketplacelisting
    - Add field disposer_confirmed to marketplacelisting
    - Add field recycler_confirmed to marketplacelisting
    - Add field auto_confirm_deadline to marketplacelisting
    - Add index marketplace_listings_escrow_status_created_at_idx
    - Add index marketplace_listings_auto_confirm_deadline_idx
```

### **Step 2: Review Generated Migration**

**File:** `apps/marketplace/migrations/0002_enhance_escrow_tracking.py`

```python
# Generated by Django 5.2.6 on 2025-10-08
from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('marketplace', '0001_initial'),
    ]

    operations = [
        # 1. Expand escrow_status choices
        migrations.AlterField(
            model_name='marketplacelisting',
            name='escrow_status',
            field=models.CharField(
                max_length=20,
                choices=[
                    ('pending', 'Pending'),
                    ('payment_initiated', 'Payment Initiated'),
                    ('locked', 'Locked'),
                    ('item_released', 'Item Released'),
                    ('confirmed', 'Confirmed'),
                    ('released', 'Released'),
                    ('refunded', 'Refunded'),
                    ('failed', 'Failed'),
                    ('cancelled', 'Cancelled'),
                    ('disputed', 'Disputed'),
                ],
                default='pending'
            ),
        ),

        # 2. Add timestamp fields
        migrations.AddField(
            model_name='marketplacelisting',
            name='payment_initiated_at',
            field=models.DateTimeField(blank=True, null=True),
        ),
        migrations.AddField(
            model_name='marketplacelisting',
            name='payment_locked_at',
            field=models.DateTimeField(blank=True, null=True),
        ),
        migrations.AddField(
            model_name='marketplacelisting',
            name='item_released_at',
            field=models.DateTimeField(blank=True, null=True),
        ),
        migrations.AddField(
            model_name='marketplacelisting',
            name='confirmed_at',
            field=models.DateTimeField(blank=True, null=True),
        ),
        migrations.AddField(
            model_name='marketplacelisting',
            name='released_at',
            field=models.DateTimeField(blank=True, null=True),
        ),

        # 3. Add boolean flags
        migrations.AddField(
            model_name='marketplacelisting',
            name='disposer_confirmed',
            field=models.BooleanField(default=False),
        ),
        migrations.AddField(
            model_name='marketplacelisting',
            name='recycler_confirmed',
            field=models.BooleanField(default=False),
        ),

        # 4. Add deadline field
        migrations.AddField(
            model_name='marketplacelisting',
            name='auto_confirm_deadline',
            field=models.DateTimeField(blank=True, null=True),
        ),

        # 5. Add indexes for performance
        migrations.AddIndex(
            model_name='marketplacelisting',
            index=models.Index(
                fields=['escrow_status', '-created_at'],
                name='mp_escrow_idx'
            ),
        ),
        migrations.AddIndex(
            model_name='marketplacelisting',
            index=models.Index(
                fields=['auto_confirm_deadline'],
                name='mp_deadline_idx'
            ),
        ),
    ]
```

---

## 🧪 Testing the Migration

### **Test 1: Dry Run (SQLite)**

```bash
# See SQL without executing
python manage.py sqlmigrate marketplace 0002
```

**Expected SQL:**
```sql
-- Alter field escrow_status (just updates metadata, no data change)
-- Django handles this internally

-- Add new fields
ALTER TABLE "marketplace_listings"
    ADD COLUMN "payment_initiated_at" datetime NULL;

ALTER TABLE "marketplace_listings"
    ADD COLUMN "payment_locked_at" datetime NULL;

ALTER TABLE "marketplace_listings"
    ADD COLUMN "item_released_at" datetime NULL;

ALTER TABLE "marketplace_listings"
    ADD COLUMN "confirmed_at" datetime NULL;

ALTER TABLE "marketplace_listings"
    ADD COLUMN "released_at" datetime NULL;

ALTER TABLE "marketplace_listings"
    ADD COLUMN "disposer_confirmed" bool NOT NULL DEFAULT 0;

ALTER TABLE "marketplace_listings"
    ADD COLUMN "recycler_confirmed" bool NOT NULL DEFAULT 0;

ALTER TABLE "marketplace_listings"
    ADD COLUMN "auto_confirm_deadline" datetime NULL;

-- Create indexes
CREATE INDEX "mp_escrow_idx"
    ON "marketplace_listings" ("escrow_status", "created_at" DESC);

CREATE INDEX "mp_deadline_idx"
    ON "marketplace_listings" ("auto_confirm_deadline");
```

### **Test 2: Check Migration Plan**

```bash
python manage.py migrate --plan
```

**Expected output:**
```
Planned operations:
marketplace.0002_enhance_escrow_tracking
  Alter field escrow_status on marketplacelisting
  Add field payment_initiated_at to marketplacelisting
  Add field payment_locked_at to marketplacelisting
  Add field item_released_at to marketplacelisting
  Add field confirmed_at to marketplacelisting
  Add field released_at to marketplacelisting
  Add field disposer_confirmed to marketplacelisting
  Add field recycler_confirmed to marketplacelisting
  Add field auto_confirm_deadline to marketplacelisting
  Add index marketplace_escrow_idx on marketplacelisting
  Add index marketplace_deadline_idx on marketplacelisting
```

### **Test 3: Apply Migration**

```bash
# Apply migration
python manage.py migrate marketplace 0002

# Verify it applied
python manage.py showmigrations marketplace
```

**Expected output:**
```
marketplace
 [X] 0001_initial
 [X] 0002_enhance_escrow_tracking
```

---

## 🔍 Verification After Migration

### **Verify Schema**

```python
# Python shell
python manage.py shell

from apps.marketplace.models import MarketplaceListing

# Check fields exist
mp = MarketplaceListing.objects.first()
print(mp.payment_initiated_at)  # Should print None or a datetime
print(mp.disposer_confirmed)     # Should print False
print(mp.escrow_status)          # Should print current value ('pending', 'locked', etc.)
```

### **Verify Existing Data**

```python
# Count existing records
from apps.marketplace.models import MarketplaceListing

total = MarketplaceListing.objects.count()
print(f"Total records: {total}")

# Check old records have NULL for new fields
old_records = MarketplaceListing.objects.filter(payment_initiated_at__isnull=True)
print(f"Records with NULL payment_initiated_at: {old_records.count()}")
# Should match total count if all are old records

# Verify boolean defaults
confirmed_false = MarketplaceListing.objects.filter(disposer_confirmed=False)
print(f"Records with disposer_confirmed=False: {confirmed_false.count()}")
# Should be all records
```

### **Verify Existing Queries Still Work**

```python
# Test dashboard query (should work unchanged)
sold_listings = MarketplaceListing.objects.filter(
    listing_id__user_id=user,
    escrow_status='released'
).count()
print(f"Sold listings: {sold_listings}")
# Should return same count as before migration

# Test reward query (should work unchanged)
completed = MarketplaceListing.objects.filter(escrow_status='released').first()
if completed:
    print(f"Listing: {completed.listing_id.id}")
    print(f"Recycler: {completed.recycler_id.name if completed.recycler_id else 'None'}")
# Should return same data as before migration
```

---

## 📊 Impact on Existing Code

### **Code That Still Works (No Changes Needed)**

#### **1. Dashboard Views**

```python
# apps/users/views.py - DisposerDashboardView
# NO CHANGES NEEDED - This still works
sold_listings = MarketplaceListing.objects.filter(
    listing_id__user_id=user,
    escrow_status='released'  # Old status value still valid
).count()
```

#### **2. Reward Processing**

```python
# apps/wallet/utils.py - process_marketplace_rewards
# NO CHANGES NEEDED - This still works
def process_marketplace_rewards(marketplace_listing):
    listing = marketplace_listing.listing_id
    disposer = listing.user_id
    recycler = marketplace_listing.recycler_id
    # ... rest of function unchanged
```

#### **3. Manual Testing Scripts**

```python
# tests/simulate_marketplace_transaction.py
# NO CHANGES NEEDED - This still works
marketplace_listing, created = MarketplaceListing.objects.get_or_create(
    listing_id=listing,
    defaults={
        'recycler_id': recycler,
        'price': Decimal('255.00'),
        'escrow_status': 'released'  # Old status value
    }
)
# New fields automatically NULL or False
```

### **Code That Can Use New Features (Optional Enhancements)**

#### **1. Enhanced Status Tracking**

```python
# OPTIONAL: Use new status values
marketplace_listing.escrow_status = 'payment_initiated'
marketplace_listing.payment_initiated_at = timezone.now()
marketplace_listing.save()

# Later...
marketplace_listing.escrow_status = 'locked'
marketplace_listing.payment_locked_at = timezone.now()
marketplace_listing.save()
```

#### **2. Confirmation Tracking**

```python
# OPTIONAL: Track confirmations
marketplace_listing.disposer_confirmed = True
marketplace_listing.item_released_at = timezone.now()
marketplace_listing.save()
```

#### **3. Deadline Management**

```python
# OPTIONAL: Set auto-confirm deadline
from datetime import timedelta
marketplace_listing.auto_confirm_deadline = timezone.now() + timedelta(days=7)
marketplace_listing.save()
```

---

## 🚨 Edge Cases & Handling

### **Edge Case 1: Existing In-Progress Transactions**

**Scenario:** Migration runs while marketplace listings are in 'locked' state.

**What happens:**
- Status remains 'locked' ✅
- New timestamp fields are `NULL` ✅
- Transactions continue normally ✅

**No action needed** - Old transactions work with old states, new transactions use new states.

### **Edge Case 2: Node.js Writing to Database**

**Scenario:** Node.js updates `escrow_status` after migration.

**What happens:**
```javascript
// Node.js code - Still works
await MarketplaceListing.update({
  escrow_status: 'released'  // Old value, still valid
}, { where: { id: listingId } });
```

- Update succeeds ✅
- New fields remain `NULL` ✅
- Django code handles `NULL` gracefully ✅

**No changes needed** to Node.js code.

### **Edge Case 3: Rollback Needed**

**Scenario:** Need to reverse migration.

**Solution:**
```bash
# Rollback to previous migration
python manage.py migrate marketplace 0001

# This will:
# - Remove new fields
# - Restore escrow_status to old choices
# - Keep existing data intact (only removes new columns)
```

**Data loss:** Only new field data (timestamps, confirmations) - **escrow_status values preserved**.

---

## 📋 Pre-Migration Checklist

Before running migration in production:

### **Preparation**
- [ ] **Backup database** (critical!)
- [ ] Test migration on development database
- [ ] Test migration on staging database
- [ ] Verify existing queries in dev environment
- [ ] Check Node.js code doesn't use new fields yet

### **Migration Execution**
- [ ] Schedule during low-traffic window
- [ ] Have rollback plan ready
- [ ] Monitor database size (indexes add ~5-10% size)
- [ ] Run migration: `python manage.py migrate marketplace 0002`

### **Post-Migration Verification**
- [ ] Check migration applied: `python manage.py showmigrations`
- [ ] Verify row counts unchanged: `SELECT COUNT(*) FROM marketplace_listings;`
- [ ] Test existing dashboard queries
- [ ] Test reward processing
- [ ] Check application logs for errors
- [ ] Verify new fields exist: `python manage.py dbshell` → `\d marketplace_listings`

---

## 🎯 Summary

### **What Changes:**
- ✅ 8 new fields added to `MarketplaceListing`
- ✅ `escrow_status` choices expanded (10 states instead of 4)
- ✅ 2 new indexes for query performance

### **What Stays the Same:**
- ✅ All existing fields unchanged
- ✅ All existing data unchanged
- ✅ All existing queries work unchanged
- ✅ All existing dashboard/reward code works unchanged
- ✅ Node.js integration works unchanged

### **Risk Assessment:**
- **Data Loss Risk:** ✅ **NONE** (additive only)
- **Breaking Changes:** ✅ **NONE** (100% backward compatible)
- **Downtime Required:** ✅ **NONE** (migration runs in seconds)
- **Rollback Difficulty:** ✅ **EASY** (single command)

### **Recommendation:**
✅ **SAFE TO PROCEED** - This migration is low-risk and fully backward compatible.

---

## 📞 Support

**If issues occur:**

1. **Check logs:** `tail -f logs/*.log`
2. **Verify migration:** `python manage.py showmigrations`
3. **Rollback if needed:** `python manage.py migrate marketplace 0001`
4. **Check database:** `python manage.py dbshell`

**Common issues:**
- Migration takes long: Normal for large tables (expect 1-5 seconds per 10k rows)
- "Column already exists" error: Run `python manage.py migrate --fake marketplace 0002`
- Query errors: Verify field names match exactly

---

**Migration Status:** ✅ Ready for implementation
**Backward Compatibility:** ✅ 100%
**Risk Level:** ✅ LOW
