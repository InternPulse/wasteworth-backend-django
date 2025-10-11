# Wasteworth End-to-End Test Report

**Test Date:** October 1, 2025
**Services Tested:**
- Django Backend: `https://wasteworth-backend-django.onrender.com/api/v1`
- Node.js Backend: `https://wasteworth-backend-express.onrender.com/api/v1`

---

## Executive Summary

An end-to-end test was conducted to verify the complete user flow involving two user types (Disposer and Recycler), testing user registration, referral rewards, listing creation, marketplace interactions, and the reward engine.

### Overall Results
- **Total Tests:** 7 core functionality tests
- **Passed:** 4 tests (57%)
- **Failed:** 3 tests (43%)
- **Warnings:** 1

---

## Test Flow Design

The test was designed to simulate the following realistic scenario:

1. **Recycler Registration** - A recycler creates an account and obtains a referral code
2. **Disposer Registration with Referral** - A disposer signs up using the recycler's referral code
3. **Referral Reward Verification** - Verify recycler receives 100 points for successful referral
4. **Listing Creation** - Disposer creates a waste listing via Node.js service
5. **Marketplace Viewing** - Recycler views available listings in marketplace
6. **Purchase Transaction** - Recycler purchases the disposer's listing
7. **Notification Verification** - Both users receive appropriate notifications
8. **Final Reward Distribution** - Verify reward engine distributes points correctly

---

## Detailed Test Results

### ✅ PASSED TESTS

#### 1. Recycler Signup
**Endpoint:** `POST /api/v1/users/signup/`
**Status:** ✅ PASSED (201 Created)

**Request:**
```json
{
  "name": "Test Recycler",
  "email": "test_20251001105054_rbpe@wasteworth.test",
  "phone": "+2340828942294",
  "password": "TestPass123!@#",
  "confirm_password": "TestPass123!@#",
  "role": "recycler"
}
```

**Response:**
```json
{
  "success": true,
  "message": "Account created successfully. Use POST /api/v1/otp/send/ to request verification OTP.",
  "user_id": "110e6216-4e2e-4293-b3f0-18af7777c8b3",
  "email": "test_20251001105054_rbpe@wasteworth.test",
  "is_verified": false,
  "next_step": "Send OTP using POST /api/v1/otp/send/ then verify with POST /api/v1/otp/verify/?action=signup"
}
```

**Validation:** Account created successfully with proper response structure.

---

#### 2. Recycler Login
**Endpoint:** `POST /api/v1/users/login/`
**Status:** ✅ PASSED (200 OK)

**Request:**
```json
{
  "email": "test_20251001105054_rbpe@wasteworth.test",
  "password": "TestPass123!@#"
}
```

**Response:**
```json
{
  "success": true,
  "message": "Login successful",
  "user": {
    "id": "110e6216-4e2e-4293-b3f0-18af7777c8b3",
    "name": "Test Recycler",
    "email": "test_20251001105054_rbpe@wasteworth.test",
    "phone": "+2340828942294",
    "role": "recycler",
    "address_location": null,
    "wallet_balance": "0.00",
    "referral_code": "8XKNHMD5",
    "created_at": "2025-10-01T10:50:57.401726Z"
  },
  "tokens": {
    "refresh_token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
    "access": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..."
  }
}
```

**Validation:**
- Login successful
- JWT tokens generated correctly
- Referral code retrieved: `8XKNHMD5`

---

#### 3. Disposer Signup with Referral
**Endpoint:** `POST /api/v1/users/signup/`
**Status:** ✅ PASSED (201 Created)

**Request:**
```json
{
  "name": "Test Disposer",
  "email": "test_20251001105110_hark@wasteworth.test",
  "phone": "+2346381816213",
  "password": "TestPass123!@#",
  "confirm_password": "TestPass123!@#",
  "role": "disposer",
  "referred_by": "8XKNHMD5"
}
```

**Response:**
```json
{
  "success": true,
  "message": "Account created successfully. Use POST /api/v1/otp/send/ to request verification OTP.",
  "user_id": "ef7d5795-677d-4f92-9c42-d63a1b85451c",
  "email": "test_20251001105110_hark@wasteworth.test",
  "is_verified": false,
  "next_step": "Send OTP using POST /api/v1/otp/send/ then verify with POST /api/v1/otp/verify/?action=signup"
}
```

**Validation:**
- Account created successfully
- Referral code accepted
- According to Django code analysis, referral reward should be distributed at signup time

---

#### 4. Disposer Login
**Endpoint:** `POST /api/v1/users/login/`
**Status:** ✅ PASSED (200 OK)

**Request:**
```json
{
  "email": "test_20251001105110_hark@wasteworth.test",
  "password": "TestPass123!@#"
}
```

**Response:**
```json
{
  "success": true,
  "message": "Login successful",
  "user": {
    "id": "ef7d5795-677d-4f92-9c42-d63a1b85451c",
    "name": "Test Disposer",
    "email": "test_20251001105110_hark@wasteworth.test",
    "phone": "+2346381816213",
    "role": "disposer",
    "address_location": null,
    "wallet_balance": "0.00",
    "referral_code": "0P02RUJL",
    "created_at": "2025-10-01T10:51:13.549423Z"
  },
  "tokens": {
    "refresh_token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
    "access": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..."
  }
}
```

**Validation:** Login successful with JWT tokens generated.

---

### ❌ FAILED TESTS

#### 5. Get Recycler Wallet Balance
**Endpoint:** `GET /api/v1/wallet/balance/`
**Status:** ❌ FAILED (500 Internal Server Error)

**Request:**
```http
GET /api/v1/wallet/balance/
Authorization: Bearer <access_token>
Content-Type: application/json
```

**Response:**
```json
{
  "success": false,
  "message": "Something went wrong on our end. Please try again later.",
  "error": {
    "code": "SERVER_ERROR",
    "message": "Something went wrong on our end. Please try again later.",
    "details": {
      "error": [
        "Failed to retrieve wallet information."
      ]
    }
  }
}
```

**Issue Analysis:**
- The wallet endpoint returns 500 error for both recycler and disposer
- Based on code analysis in `apps/wallet/views.py:59-92`, the endpoint should:
  1. Get or create wallet for authenticated user
  2. Return wallet balance and points
- Likely causes:
  - Database connection issue
  - Missing wallet table or migration not run
  - Potential issue with wallet creation logic

**Code Reference:** [wallet/views.py:59-92](apps/wallet/views.py#L59)

**Expected Behavior:**
According to `apps/users/serializers.py:61-104`, when a disposer signs up with a referral code:
1. Referral record is created
2. `distribute_referral_reward()` is called immediately
3. Referrer should receive 100 points

**Impact:** Cannot verify referral reward distribution.

---

#### 6. Create Listing via Node.js
**Endpoint:** `POST /api/v1/listings`
**Status:** ❌ FAILED (401 Unauthorized)

**Request:**
```json
{
  "waste_type": "Plastic",
  "quantity": 25.5,
  "unit": "kg",
  "description": "E2E Test: High-quality plastic waste for recycling",
  "location": {
    "address": "123 Test Street, Lagos, Nigeria",
    "latitude": 6.5244,
    "longitude": 3.3792
  },
  "price_per_unit": 50,
  "images": ["https://example.com/image1.jpg"]
}
```

**Response:**
```json
{
  "status": "fail",
  "error": {
    "statusCode": 401,
    "status": "fail",
    "isOperational": true
  },
  "message": "user not verified, verify to gain access",
  "stack": "Error: user not verified, verify to gain access\n    at /opt/render/project/src/controllers/authController.js:33:17..."
}
```

**Issue Analysis:**
- Node.js service requires user verification before allowing access
- Users are created with `is_verified: false` by default
- OTP verification is required but not implemented in test
- Stack trace indicates check at `/opt/render/project/src/controllers/authController.js:33:17`

**Root Cause:** Test does not include OTP verification step.

**Solution Required:**
1. Implement OTP sending: `POST /api/v1/otp/send/`
2. Retrieve OTP (from email or test environment)
3. Verify OTP: `POST /api/v1/otp/verify/?action=signup`

**Impact:** Blocks all Node.js service tests (listings, marketplace, notifications).

---

#### 7. View Marketplace Listings
**Endpoint:** `GET /api/v1/marketplace`
**Status:** ❌ FAILED (404 Not Found)

**Request:**
```http
GET /api/v1/marketplace
Authorization: Bearer <access_token>
Content-Type: application/json
```

**Response:**
```json
{
  "status": "fail",
  "error": {
    "statusCode": 404,
    "status": "fail",
    "isOperational": true
  },
  "message": "Can't find /api/v1/marketplace on this server",
  "stack": "Error: Can't find /api/v1/marketplace on this server\n    at /opt/render/project/src/app.js:29:5..."
}
```

**Issue Analysis:**
- Endpoint `/api/v1/marketplace` does not exist on Node.js service
- Possible correct endpoints:
  - `/api/v1/marketplace/listings`
  - `/api/v1/listings` (may serve as marketplace)
  - Different route structure

**Solution Required:** Obtain correct Node.js API documentation or explore available endpoints.

**Impact:** Cannot test marketplace viewing functionality.

---

### ⚠️ WARNINGS

#### 8. Purchase Test Skipped
**Warning:** "No listing ID available - skipping purchase test"

**Reason:** Since listing creation failed (due to verification), no listing ID was available to test purchase flow.

**Impact:** Unable to test:
- Purchase transaction
- Escrow handling
- Transaction reward distribution (disposer and recycler)
- First transaction bonus for referrer

---

## Code Analysis Findings

### Django Service (Authentication & Rewards)

#### User Registration with Referral Flow
**File:** `apps/users/serializers.py:61-104`

```python
def create(self, validated_data):
    # ... user creation ...

    # Handle referral reward if user signed up with a referral code
    if referred_by_code:
        try:
            # Find the referrer by their referral code
            referrer = User.objects.get(referral_code=referred_by_code)

            # Create referral record
            referral = Referral.objects.create(
                referrer=referrer,
                referee=user,
                status='pending',
                referral_reward=0
            )

            # Award 100 points to referrer immediately
            distribute_referral_reward(
                referrer_user=referrer,
                referee_user=user,
                referral_obj=referral
            )
```

**Key Findings:**
- Referral reward (100 points) is distributed **immediately** on signup
- Uses `distribute_referral_reward()` from `apps/wallet/utils.py:69-133`
- Wallet is created automatically if it doesn't exist
- Transaction record is created with type `referral_reward`

---

#### Reward Distribution Logic
**File:** `apps/wallet/utils.py`

##### 1. Referral Rewards (Line 69-133)
```python
def distribute_referral_reward(referrer_user, referee_user, referral_obj=None, is_signup=True):
    """
    Called in two scenarios:
    1. When referee signs up (is_signup=True) - gives 100 points
    2. When referee completes first transaction (is_signup=False) - gives BONUS 100 points
    """
    points = 100  # Fixed reward

    # Get or create referrer's wallet
    wallet, created = Wallet.objects.get_or_create(user=referrer_user, ...)

    # Update wallet points
    wallet.points += points
    wallet.save()

    # Create transaction record
    WalletTransaction.objects.create(
        wallet=wallet,
        user=referrer_user,
        transaction_type='referral_reward',
        points=points,
        payment_method='system',
        status='success',
        description=...
    )
```

**Expected Behavior:**
- Referrer gets 100 points on referee signup
- Referrer gets **another** 100 points when referee completes first transaction
- Total possible referral reward: 200 points per successful referral

---

##### 2. Activity Rewards (Line 13-66)
```python
def distribute_activity_reward(user, quantity_kg, transaction_type='activity_reward', description=''):
    """
    Distribute activity reward points to a user.
    Calculate points: 1kg = 10 points
    """
    points = int(Decimal(str(quantity_kg)) * 10)

    wallet.points += points
    wallet.save()

    WalletTransaction.objects.create(
        transaction_type=transaction_type,
        points=points,
        status='success',
        ...
    )
```

**Formula:** `points = quantity_kg × 10`

**Example:** 25.5 kg waste = 255 points

---

##### 3. Marketplace Rewards (Line 136-238)
```python
def process_marketplace_rewards(marketplace_listing):
    """
    Process rewards for both disposer (seller) and recycler (buyer)
    when escrow is released.
    """
    disposer = listing.user_id  # Seller
    recycler = marketplace_listing.recycler_id  # Buyer
    quantity_kg = listing.quantity

    # 1. Distribute activity reward to disposer (seller)
    distribute_activity_reward(user=disposer, quantity_kg=quantity_kg, ...)

    # 2. Distribute activity reward to recycler (buyer)
    distribute_activity_reward(user=recycler, quantity_kg=quantity_kg, ...)

    # 3. Check if first transaction - give BONUS 100 points to referrer
    if disposer.referred_by and activity_count == 1:
        distribute_referral_reward(..., is_signup=False)

    if recycler.referred_by and activity_count == 1:
        distribute_referral_reward(..., is_signup=False)
```

**Complete Reward Flow for 25.5kg Transaction:**

| User | Event | Points | Description |
|------|-------|--------|-------------|
| Recycler (Referrer) | Disposer signs up with referral | +100 | Initial referral reward |
| Disposer | Sells 25.5kg waste | +255 | Activity reward (25.5 × 10) |
| Recycler | Purchases 25.5kg waste | +255 | Activity reward (25.5 × 10) |
| Recycler (Referrer) | Disposer's first transaction | +100 | First transaction bonus |
| **Total** | | **710** | Recycler: 455, Disposer: 255 |

---

### Node.js Service Issues

#### Authentication Middleware
**Error:** `"user not verified, verify to gain access"`
**Location:** `/opt/render/project/src/controllers/authController.js:33:17`

**Issue:** Node.js service validates `is_verified` field from user record.

**Current State:**
- Users created with `is_verified: false`
- Login succeeds but JWT token contains unverified user
- Node.js endpoints reject unverified users

**Required Flow:**
1. User signs up → `is_verified: false`
2. Request OTP: `POST /api/v1/otp/send/` with body `{"user_id": "<uuid>"}`
3. Verify OTP: `POST /api/v1/otp/verify/?action=signup` with body `{"user_id": "<uuid>", "otp": "123456"}`
4. User marked as verified: `is_verified: true`
5. Re-login to get updated JWT token
6. Access Node.js endpoints

---

#### Endpoint Discovery
**Error:** `"Can't find /api/v1/marketplace on this server"`

**Issue:** Marketplace endpoint path is unknown without proper documentation.

**Possible Endpoints:**
- `/api/v1/marketplace/listings`
- `/api/v1/marketplace/available`
- `/api/v1/listings?status=available`

**Solution:** Need to either:
1. Access actual Node.js API documentation
2. Explore endpoints programmatically
3. Contact development team for route list

---

## Identified Gaps & Recommendations

### Critical Issues

#### 1. Wallet Service Failure (500 Error)
**Severity:** HIGH
**Impact:** Blocks verification of entire reward system

**Investigation Required:**
- Check database migrations: `python manage.py showmigrations wallet`
- Check database logs for errors
- Verify Wallet model is properly registered
- Test wallet creation manually in Django shell

**Recommended Fix:**
```python
# Test in Django shell
from apps.wallet.models import Wallet
from apps.users.models import User

user = User.objects.first()
wallet, created = Wallet.objects.get_or_create(user=user)
print(wallet, created)
```

---

#### 2. OTP Verification Required
**Severity:** HIGH
**Impact:** Blocks all Node.js service tests

**Missing Test Steps:**
1. Send OTP after signup
2. Retrieve OTP (requires email access or test hook)
3. Verify OTP
4. Re-login to get updated token

**Recommended Enhancement:**
```python
def test_otp_verification(self, user_data):
    # Send OTP
    response = requests.post(
        f"{DJANGO_BASE_URL}/otp/send/",
        json={"user_id": user_data['user_id']}
    )

    # In test environment, OTP could be:
    # - Retrieved from test email service
    # - Mocked with known value
    # - Read from database in test mode

    # Verify OTP
    response = requests.post(
        f"{DJANGO_BASE_URL}/otp/verify/?action=signup",
        json={
            "user_id": user_data['user_id'],
            "otp": "123456"  # Test OTP
        }
    )
```

---

#### 3. Node.js API Documentation
**Severity:** MEDIUM
**Impact:** Cannot test Node.js features accurately

**Current State:** Postman documentation URL returns JavaScript instead of API docs

**Recommendations:**
1. Use Postman API to export collection as JSON
2. Request OpenAPI/Swagger spec from Node.js service
3. Add `/health` or `/routes` endpoint to Node.js service
4. Document all Node.js endpoints in team wiki

---

### Enhancement Opportunities

#### 1. Test Environment Setup
- Create test-specific user accounts with pre-verified status
- Mock OTP service for automated testing
- Add test mode toggle in Django settings
- Seed database with test data

#### 2. Unified Authentication
- Consider moving user verification to Django service only
- Share verification status via JWT claims
- Add `is_verified` to JWT token payload

#### 3. Error Handling
- Improve error messages (500 errors are too generic)
- Add request ID tracking for debugging
- Implement structured logging

#### 4. API Documentation
- Deploy Swagger UI for both services
- Keep Postman collection up-to-date
- Add API versioning strategy
- Document authentication flow clearly

---

## Test Data Reference

### Test Accounts Created

#### Recycler Account
```json
{
  "user_id": "110e6216-4e2e-4293-b3f0-18af7777c8b3",
  "name": "Test Recycler",
  "email": "test_20251001105054_rbpe@wasteworth.test",
  "phone": "+2340828942294",
  "role": "recycler",
  "referral_code": "8XKNHMD5",
  "is_verified": false,
  "created_at": "2025-10-01T10:50:57.401726Z"
}
```

#### Disposer Account (with referral)
```json
{
  "user_id": "ef7d5795-677d-4f92-9c42-d63a1b85451c",
  "name": "Test Disposer",
  "email": "test_20251001105110_hark@wasteworth.test",
  "phone": "+2346381816213",
  "role": "disposer",
  "referral_code": "0P02RUJL",
  "referred_by": "8XKNHMD5",
  "is_verified": false,
  "created_at": "2025-10-01T10:51:13.549423Z"
}
```

---

## Conclusion

### What Worked ✅
1. **User Registration** - Both Django endpoints working correctly
2. **Authentication** - JWT token generation and login flow successful
3. **Referral Code System** - Referral codes generated and accepted
4. **Error Handling** - Proper error messages returned (though not always helpful)

### What Failed ❌
1. **Wallet Service** - 500 errors prevent reward verification
2. **User Verification** - OTP flow not implemented in test
3. **Node.js Integration** - Cannot test listings, marketplace, or notifications
4. **End-to-End Flow** - Complete user journey blocked by verification requirement

### Blockers
1. Database/wallet service issue causing 500 errors
2. Missing OTP verification in test flow
3. Incomplete Node.js API documentation

### Next Steps

**Immediate (Required for E2E):**
1. Debug wallet service 500 error
2. Implement OTP verification in test
3. Obtain correct Node.js API endpoints

**Short-term:**
1. Create test environment with verified users
2. Document actual Node.js API routes
3. Add health check endpoints

**Long-term:**
1. Implement comprehensive integration tests
2. Add API monitoring and alerting
3. Create staging environment with test data
4. Document complete API flows

---

## Test Script Location

The complete test script is available at:
```
C:\Users\sadiq\OneDrive\Documents\Projects\wasteworth-backend-django\e2e_test.py
```

### Running the Test

```bash
cd C:\Users\sadiq\OneDrive\Documents\Projects\wasteworth-backend-django
python e2e_test.py
```

### Test Output
Full console output with color-coded results showing:
- Request/response details for each step
- Pass/fail status
- Detailed error messages
- Summary with counts

---

**Report Generated:** October 1, 2025
**Test Execution Time:** ~30 seconds
**Services Status:**
- ✅ Django Backend: Partially Working (auth works, wallet fails)
- ❌ Node.js Backend: Blocked by verification requirement
