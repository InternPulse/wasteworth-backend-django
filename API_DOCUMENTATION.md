# Wasteworth API Documentation

## Base URL
**Development:**
```
http://localhost:8000/api/v1/
```

**Production:**
```
https://wasteworth-backend-django.onrender.com/api/v1/
```

## Authentication
The API uses JWT (JSON Web Token) authentication. Include the access token in the Authorization header:
```
Authorization: Bearer <access_token>
```

## 🔄 Consistent Error Format
**ALL endpoints now return errors in this standardized format:**

```json
{
  "success": false,
  "message": "User-friendly error message for easy frontend display",
  "error": {
    "code": "ERROR_CODE",
    "message": "User-friendly error message",
    "details": {
      "field": ["Specific field error"]
    }
  }
}
```

**Key Points:**
- **Top-level `message`**: Always user-friendly for direct frontend display
- **`error.message`**: Same user-friendly message for consistency
- **`error.details`**: Raw field errors preserved for debugging
- **`error.code`**: Programmatic error handling

**Common Error Codes:**
- `VALIDATION_ERROR` - Invalid input data
- `EMAIL_ALREADY_EXISTS` - Duplicate email during signup
- `INVALID_CREDENTIALS` - Wrong login credentials
- `TOKEN_REQUIRED` - Missing authentication token
- `INVALID_TOKEN` - Invalid/expired token
- `OTP_REQUIRED` - OTP verification needed
- `INVALID_OTP` - Wrong/expired OTP
- `PERMISSION_DENIED` - Insufficient permissions

## Quick Start Guide

### 1. Sign Up → Send OTP → Verify → Login
```bash
# Step 1: Create account (user created but unverified)
POST /users/signup/

# Step 2: Send OTP email separately
POST /otp/send/

# Step 3: Verify OTP to complete registration
POST /otp/verify/?action=signup

# Step 4: Login normally (no OTP needed)
POST /users/login/
```

### 2. Reset Password
```bash
# Step 1: Request password reset (sends OTP)
POST /users/forgotPassword/

# Step 2: Verify OTP and set new password
POST /users/resetPassword/
```

### 3. Update Profile (Role Changes Only)
```bash
# Step 1: Request OTP for role changes only
PATCH /users/update-user/ (with role field)

# Step 2: Verify OTP and complete update
PATCH /users/update-user/ (with same data + OTP)

# Note: Email and phone can be updated directly without OTP
PATCH /users/update-user/ (with email/phone - no OTP required)
```

### 4. Referral System
```bash
# Get your referral link from dashboard
GET /users/disposer-dashboard/  # or /users/recycler-dashboard/
# Returns: referral_code and referral_link

# Share link: https://yourapp.com/signup?ref=ABC123DE
# New user clicks link → Frontend extracts ref parameter

# New user signs up with referral
POST /users/signup/
{
  "referred_by": "ABC123DE"  // Extracted from URL
}
# Referrer gets 100 points immediately
# Referrer gets BONUS 100 points on referee's first transaction
```

---

## 📋 All Endpoints

### 🔐 Authentication Endpoints

#### 1. User Signup
**POST** `/users/signup/`

Creates a new **unverified** user account. **OTP must be sent separately** using `/otp/send/`.

**Request Body:**
```json
{
    "name": "John Doe",
    "email": "user@example.com",
    "password": "StrongPass123!",
    "confirm_password": "StrongPass123!",
    "phone": "+1234567890",
    "role": "disposer"
}
```

**Valid Roles:** `disposer`, `recycler`

**Success Response (201):**
```json
{
    "success": true,
    "message": "Account created successfully. Use POST /api/v1/otp/send/ to request verification OTP.",
    "user_id": "e4e0dbb2-9384-4278-b84b-e5679f2664e7",
    "email": "user@example.com",
    "is_verified": false,
    "next_step": "Send OTP using POST /api/v1/otp/send/ then verify with POST /api/v1/otp/verify/?action=signup"
}
```

**Error Response (400):**
```json
{
    "success": false,
    "error": {
        "code": "EMAIL_ALREADY_EXISTS",
        "message": "An account with this email already exists. Try logging in instead.",
        "details": {
            "email": ["user with this email already exists."]
        }
    }
}
```

**Validation Error Response (400):**
```json
{
    "success": false,
    "error": {
        "code": "VALIDATION_ERROR",
        "message": "The provided data is invalid. Please check the details below.",
        "details": {
            "name": ["This field may not be blank."],
            "email": ["Enter a valid email address."],
            "password": [
                "Password must be at least 8 characters long",
                "Password must contain at least one uppercase letter",
                "Password must contain at least one number",
                "Password must contain at least one special character"
            ],
            "role": ["\"invalid\" is not a valid choice."]
        }
    }
}
```

#### 2. Verify OTP (Complete Signup)
**POST** `/otp/verify/?action=signup`

Verifies OTP and completes user registration. Returns access tokens.

**Request Body:**
```json
{
    "email_or_phone": "user@example.com",
    "otp": "123456"
}
```

**Success Response (200):**
```json
{
    "success": true,
    "message": "Account verification successful",
    "user": {
        "id": "e4e0dbb2-9384-4278-b84b-e5679f2664e7",
        "name": "John Doe",
        "email": "user@example.com",
        "phone": "+1234567890",
        "role": "disposer",
        "address_location": null,
        "wallet_balance": "0.00",
        "referral_code": "ABC123DEF",
        "created_at": "2025-01-15T10:30:00Z"
    },
    "tokens": {
        "refresh_token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
        "access": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..."
    }
}
```

#### 3. User Login
**POST** `/users/login/`

Direct login - **no OTP required**.

**Request Body:**
```json
{
    "email": "user@example.com",
    "password": "StrongPass123!"
}
```

**Success Response (200):**
```json
{
    "success": true,
    "message": "Login successful",
    "user": {
        "id": "e4e0dbb2-9384-4278-b84b-e5679f2664e7",
        "name": "John Doe",
        "email": "user@example.com",
        "phone": "+1234567890",
        "role": "disposer",
        "address_location": null,
        "wallet_balance": "0.00",
        "referral_code": "ABC123DEF",
        "created_at": "2025-01-15T10:30:00Z"
    },
    "tokens": {
        "refresh_token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
        "access": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..."
    }
}
```

**Error Response (400):**
```json
{
    "success": false,
    "error": {
        "code": "VALIDATION_ERROR",
        "message": "The provided data is invalid. Please check the details below.",
        "details": {
            "non_field_errors": ["The password you entered is incorrect. Please try again."]
        }
    }
}
```

#### 4. User Logout
**POST** `/users/logout/`

Blacklists the refresh token to logout the user securely.

**Request Body:**
```json
{
    "refresh_token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..."
}
```

**Success Response (200):**
```json
{
    "success": true,
    "message": "Logout successful"
}
```

**Error Response (401):**
```json
{
    "success": false,
    "error": {
        "code": "TOKEN_REQUIRED",
        "message": "Authentication token is required for this action.",
        "details": {
            "refresh_token": ["Refresh token is required to log out securely."]
        }
    }
}
```

---

### 👤 User Profile Management

#### 5. Disposer Dashboard
**GET** `/users/disposer-dashboard/`
**Authentication Required:** Yes
**Rate Limit:** 30 requests per minute per user

Gets disposer user's dashboard with profile data and waste management statistics. All data is fetched directly from the database using Django ORM queries.

**What it returns:**
- User profile information
- Total listings created by disposer
- Number of sold listings (escrow_status='released')
- Recent 5 posts by the disposer

**Success Response (200):**
```json
{
    "user": {
        "id": "e4e0dbb2-9384-4278-b84b-e5679f2664e7",
        "name": "John Doe",
        "email": "user@example.com",
        "phone": "+1234567890",
        "role": "disposer",
        "address_location": {
            "lat": 40.7128,
            "lng": -74.0060
        },
        "wallet_balance": "150.00",
        "referral_code": "ABC123DEF",
        "referral_link": "https://wasteworth-backend-django.onrender.com/signup?ref=ABC123DEF",
        "created_at": "2025-01-15T10:30:00Z"
    },
    "stats": {
        "total_listings": 12,
        "sold_listings": 8,
        "recent_posts": [
            {
                "id": "550e8400-e29b-41d4-a716-446655440000",
                "title": "Plastic bottles for recycling",
                "waste_type": "plastic",
                "quantity": 25.5,
                "status": "pending",
                "reward_estimate": "500.00",
                "image_url": "https://example.com/image.jpg",
                "created_at": "2025-01-15T14:30:00Z"
            }
        ]
    }
}
```

#### 6. Recycler Dashboard
**GET** `/users/recycler-dashboard/`
**Authentication Required:** Yes
**Rate Limit:** 30 requests per minute per user

Gets recycler user's dashboard with profile data and collection statistics. All data is fetched directly from the database using Django ORM queries.

**What it returns:**
- User profile information
- Total kg of waste collected (from completed marketplace transactions)
- Total points accumulated in wallet
- Recent 5 system-wide pending/accepted listings available for pickup

**Success Response (200):**
```json
{
    "user": {
        "id": "e4e0dbb2-9384-4278-b84b-e5679f2664e7",
        "name": "Jane Smith",
        "email": "recycler@example.com",
        "phone": "+1234567890",
        "role": "recycler",
        "address_location": {
            "lat": 40.7128,
            "lng": -74.0060
        },
        "wallet_balance": "500.00",
        "referral_code": "XYZ789ABC",
        "referral_link": "https://wasteworth-backend-django.onrender.com/signup?ref=XYZ789ABC",
        "created_at": "2025-01-10T10:30:00Z"
    },
    "stats": {
        "total_kg_collected": 156.75,
        "total_points": 1250,
        "recent_posts": [
            {
                "id": "550e8400-e29b-41d4-a716-446655440000",
                "title": "Glass bottles collection",
                "waste_type": "glass",
                "quantity": 30.0,
                "status": "accepted",
                "reward_estimate": "600.00",
                "image_url": "https://example.com/image.jpg",
                "pickup_location": {
                    "lat": 40.7580,
                    "lng": -73.9855
                },
                "created_at": "2025-01-15T12:00:00Z"
            }
        ]
    }
}
```

#### 7. User Dashboard (Legacy - Backward Compatibility)
**GET** `/users/user-dashboard/`
**Authentication Required:** Yes

⚠️ **DEPRECATED:** This endpoint is maintained for backward compatibility only. It currently maps to the Disposer Dashboard.

**New apps should use:**
- `/users/disposer-dashboard/` for disposer users
- `/users/recycler-dashboard/` for recycler users

Returns the same response as Disposer Dashboard (see above).

**Error Response (401):**
```json
{
    "success": false,
    "error": {
        "code": "VALIDATION_ERROR",
        "message": "The provided data is invalid. Please check the details below.",
        "details": {
            "detail": ["Authentication credentials were not provided."]
        }
    }
}
```

#### 8. Update User Profile
**PATCH** `/users/update-user/`
**Authentication Required:** Yes

Updates user profile. **Only role changes** require OTP verification. Email and phone can be updated directly.

**OTP-Required Fields:** `role` (only)
**Direct Update Fields:** `name`, `email`, `phone`, `address_location`

**Example 1 - Update Email/Phone/Name/Address (Direct - No OTP):**
```json
{
    "name": "Updated Name",
    "email": "newemail@example.com",
    "phone": "+9876543210",
    "address_location": {
        "lat": 40.7128,
        "lng": -74.0060
    }
}
```

**Response (200):**
```json
{
    "success": true,
    "message": "Profile updated successfully",
    "data": {
        "id": "e4e0dbb2-9384-4278-b84b-e5679f2664e7",
        "name": "Updated Name",
        "email": "newemail@example.com",
        "phone": "+9876543210",
        "role": "disposer",
        "address_location": {
            "lat": 40.7128,
            "lng": -74.0060
        },
        "wallet_balance": "150.00",
        "referral_code": "ABC123DEF",
        "created_at": "2025-01-15T10:30:00Z"
    }
}
```

**Example 2 - Update Role (Requires OTP - Two Steps):**

**Step 1 - Request OTP:**
```json
{
    "role": "recycler"
}
```

**Step 1 Response (200):**
```json
{
    "success": true,
    "message": "Profile update requires verification. OTP is being sent to your email.",
    "otp_id": "abc-123-def-456",
    "next_step": "Provide the same data along with the OTP to complete the update"
}
```

**Step 2 - Verify OTP + Complete Update:**
```json
{
    "role": "recycler",
    "otp": "123456"
}
```

**Step 2 Response (200):**
```json
{
    "success": true,
    "message": "Profile updated successfully",
    "data": {
        "id": "e4e0dbb2-9384-4278-b84b-e5679f2664e7",
        "name": "John Doe",
        "email": "user@example.com",
        "phone": "+1234567890",
        "role": "recycler",
        "address_location": null,
        "wallet_balance": "150.00",
        "referral_code": "ABC123DEF",
        "created_at": "2025-01-15T10:30:00Z"
    }
}
```

**Note:** Email and phone updates no longer require OTP verification. Only role changes require OTP for security purposes.

---

### 🔑 Password Management

#### 7. Forgot Password (Request Reset)
**POST** `/users/forgotPassword/`

Sends OTP to email for password reset.

**Request Body:**
```json
{
    "email": "user@example.com"
}
```

**Success Response (200):**
```json
{
    "success": true,
    "message": "If the email exists, password reset instructions will be sent.",
    "next_step": "Use POST /api/v1/users/resetPassword/ with email, otp, and new_password"
}
```

#### 8. Reset Password (Verify OTP + Set New Password)
**POST** `/users/resetPassword/`

Verifies OTP and resets password in one step.

**Request Body:**
```json
{
    "email": "user@example.com",
    "otp": "123456",
    "new_password": "NewStrongPass123!",
    "confirm_password": "NewStrongPass123!"
}
```

**Success Response (200):**
```json
{
    "success": true,
    "message": "Password reset successfully."
}
```

**Error Responses:**

**Invalid OTP (400):**
```json
{
    "success": false,
    "error": {
        "code": "INVALID_OTP",
        "message": "The OTP provided is invalid or has expired.",
        "details": {
            "otp": ["Invalid or expired OTP code."]
        }
    }
}
```

**User Not Found (400):**
```json
{
    "success": false,
    "error": {
        "code": "USER_NOT_FOUND",
        "message": "No user found with the provided email address.",
        "details": {
            "email": ["User with this email does not exist."]
        }
    }
}
```

**Passwords Don't Match (400):**
```json
{
    "success": false,
    "error": {
        "code": "PASSWORD_MISMATCH",
        "message": "The provided passwords do not match.",
        "details": {
            "confirm_password": ["Passwords do not match."]
        }
    }
}
```

#### 9. Update Password (Two-Step Process)
**PATCH** `/users/updatePassword/`
**Authentication Required:** Yes

**Step 1 - Send OTP:**
```json
{
    "old_password": "CurrentPassword123!"
}
```

**Step 1 Response (200):**
```json
{
    "success": true,
    "message": "OTP is being sent to your email. Please provide OTP and new_password to complete password update.",
    "otp_id": "abc-123-def-456"
}
```

**Step 2 - Verify OTP + Update Password:**
```json
{
    "old_password": "CurrentPassword123!",
    "otp": "123456",
    "new_password": "NewPassword123!",
    "new_password_confirm": "NewPassword123!"
}
```

**Step 2 Response (200):**
```json
{
    "success": true,
    "message": "Password updated successfully"
}
```

---

### 📱 OTP Management

#### 10. Send OTP
**POST** `/otp/send/`

Manually send OTP for any purpose.

**Request Body:**
```json
{
    "email_or_phone": "user@example.com",
    "purpose": "signup"
}
```

**Valid Purposes:** `signup`, `reset`, `profile_update`

**Success Response (200):**
```json
{
    "success": true,
    "message": "OTP sent successfully. If you don't see it in your inbox, please check your spam folder.",
    "otp_id": "abc-123-def-456",
    "expires_at": "2025-01-15T10:40:00Z"
}
```

#### 11. Resend OTP
**POST** `/otp/resend/`

Resends OTP and invalidates previous ones.

**Request Body:**
```json
{
    "email_or_phone": "user@example.com",
    "purpose": "signup"
}
```

**Success Response (200):**
```json
{
    "success": true,
    "message": "New OTP sent successfully. If you don't see it in your inbox, please check your spam folder.",
    "otp_id": "xyz-789-abc-123"
}
```


---

## 🔒 Security Features

### OTP Security
- **6-digit numeric codes**
- **10-minute expiration**
- **Single-use only** (cannot be reused)
- **Purpose validation** (signup OTP ≠ reset OTP ≠ profile_update OTP)
- **Previous OTP invalidation** on resend
- **Secure hashing** in database storage

### Email Reliability
- **120-second timeout** for email operations (vs 30-second default)
- **Direct email sending** with improved timeout handling
- **Reduced timeout errors** on deployed environments
- **Consistent delivery** even under high load

### Password Requirements
- **Minimum 8 characters**
- **At least one uppercase letter**
- **At least one lowercase letter**
- **At least one number**
- **At least one special character**

### Authentication Flow
- **New users start unverified** until OTP verification
- **Login does not require OTP** (direct access)
- **Password operations require OTP** for security
- **Profile updates require OTP** for sensitive fields (email, phone, role)
- **Defense in depth** for password updates (auth + old password + OTP)

---

## 📊 Token Management

### Access Token
- **Lifetime:** 60 minutes
- **Usage:** Include in Authorization header for authenticated requests
- **Format:** `Authorization: Bearer <access_token>`

### Refresh Token
- **Lifetime:** 7 days
- **Usage:** Use to obtain new access tokens when they expire
- **Security:** Tokens are blacklisted on logout

### Token Refresh
To refresh an expired access token:

**POST** `/auth/token/refresh/`
```json
{
    "refresh": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..."
}
```

---

## 📱 Usage Examples

### Complete Signup Flow
```javascript
// 1. Sign up
const signupResponse = await fetch('https://wasteworth-backend-django.onrender.com/api/v1/users/signup/', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({
        name: 'John Doe',
        email: 'user@example.com',
        password: 'StrongPass123!',
        confirm_password: 'StrongPass123!',
        phone: '+1234567890',
        role: 'disposer'
    })
});

// 2. Verify OTP (user enters OTP from email)
const verifyResponse = await fetch('https://wasteworth-backend-django.onrender.com/api/v1/otp/verify/?action=signup', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({
        email_or_phone: 'user@example.com',
        otp: '123456'
    })
});

const { tokens } = await verifyResponse.json();
// Store tokens for authenticated requests
```

### Password Reset Flow
```javascript
// 1. Request reset
await fetch('https://wasteworth-backend-django.onrender.com/api/v1/users/forgotPassword/', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({
        email: 'user@example.com'
    })
});

// 2. Reset with OTP
await fetch('https://wasteworth-backend-django.onrender.com/api/v1/users/resetPassword/', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({
        email: 'user@example.com',
        otp: '123456',
        new_password: 'NewPassword123!',
        confirm_password: 'NewPassword123!'
    })
});
```

### Profile Update Flow
```javascript
// 1. Update name, email, phone, or address (direct - no OTP)
await fetch('https://wasteworth-backend-django.onrender.com/api/v1/users/update-user/', {
    method: 'PATCH',
    headers: {
        'Content-Type': 'application/json',
        'Authorization': `Bearer ${accessToken}`
    },
    body: JSON.stringify({
        name: 'Updated Name',
        email: 'newemail@example.com',
        phone: '+9876543210'
    })
});

// 2. Update role (requires OTP)
// Step 1: Request OTP
await fetch('https://wasteworth-backend-django.onrender.com/api/v1/users/update-user/', {
    method: 'PATCH',
    headers: {
        'Content-Type': 'application/json',
        'Authorization': `Bearer ${accessToken}`
    },
    body: JSON.stringify({
        role: 'recycler'
    })
});

// Step 2: Verify OTP and complete update
await fetch('https://wasteworth-backend-django.onrender.com/api/v1/users/update-user/', {
    method: 'PATCH',
    headers: {
        'Content-Type': 'application/json',
        'Authorization': `Bearer ${accessToken}`
    },
    body: JSON.stringify({
        role: 'recycler',
        otp: '123456'
    })
});
```

### Authenticated Request
```javascript
// For disposers
const response = await fetch('https://wasteworth-backend-django.onrender.com/api/v1/users/disposer-dashboard/', {
    method: 'GET',
    headers: {
        'Content-Type': 'application/json',
        'Authorization': `Bearer ${accessToken}`
    }
});

// For recyclers
const response = await fetch('https://wasteworth-backend-django.onrender.com/api/v1/users/recycler-dashboard/', {
    method: 'GET',
    headers: {
        'Content-Type': 'application/json',
        'Authorization': `Bearer ${accessToken}`
    }
});
```

---

## 💰 Wallet Management

### Overview
The wallet system manages both **cash balances** and **eco-points** for users. Points are the primary focus, earned through referrals and recycling activities, while cash provides secondary payment functionality.

### Transaction Types
**Points-based transactions:**
- `referral_reward` - Points earned from referrals
- `activity_reward` - Points earned from recycling activities
- `redeem` - Points redeemed for rewards

**Cash-based transactions:**
- `deposit` - Cash added to wallet
- `withdrawal` - Cash withdrawn from wallet
- `payout` - Cash paid out to user
- `refund` - Cash refunded to user

### 1. Get Wallet Balance
**GET** `/wallet/balance/`
**Authentication Required:** Yes

Retrieves the user's wallet information including cash balance and points.

**Response (200):**
```json
{
    "wallet_id": "bb5ca944-62da-47b4-8bdc-79b54affbd86",
    "user_name": "Test Wallet",
    "user_email": "testwallet@example.com",
    "balance": "0.00",
    "currency": "NGN",
    "points": 0,
    "is_active": true,
    "created_at": "2025-09-29T13:34:05.342283Z",
    "updated_at": "2025-09-29T13:34:05.342309Z"
}
```

### 2. List Wallet Transactions
**GET** `/wallet/transactions/`
**Authentication Required:** Yes
**Rate Limit:** 100 requests per minute per user

Retrieves paginated list of user's wallet transactions ordered by most recent first.

**Query Parameters:**
- `page` - Page number (default: 1)
- `page_size` - Items per page (default: 20, max: 100)

**Example Request:**
```bash
GET /wallet/transactions/?page=1&page_size=20
```

**Response (200):**
```json
{
    "success": true,
    "message": "Retrieved 1 transactions",
    "count": 1,
    "next": null,
    "previous": null,
    "results": [
        {
            "transaction_id": "a4d60ab5-2b87-4334-80aa-009853b79014",
            "wallet_id": "bb5ca944-62da-47b4-8bdc-79b54affbd86",
            "user_name": "Test Wallet",
            "user_email": "testwallet@example.com",
            "transaction_type": "referral_reward",
            "transaction_type_display": "Referral Reward",
            "amount": null,
            "points": 50,
            "currency": "NGN",
            "description": "Referral reward for inviting a friend",
            "reference": "WWA4D60AB5",
            "payment_method": "referral_reward",
            "payment_method_display": "Referral Reward",
            "status": "success",
            "status_display": "Success",
            "metadata": null,
            "created_at": "2025-09-29T13:41:54.737124Z"
        }
    ]
}
```

**Example: Paginated Request**
```bash
GET /wallet/transactions/?page=2&page_size=50
```

**Error Response - Wallet Not Found (404):**
```json
{
    "success": false,
    "error": {
        "code": "NOT_FOUND",
        "message": "Wallet not found for authenticated user.",
        "details": {
            "wallet": ["No wallet associated with your account."]
        }
    }
}
```

**Error Response - Rate Limit Exceeded (429):**
```json
{
    "success": false,
    "message": "Rate limit exceeded. Please try again later.",
    "error": {
        "code": "RATE_LIMIT_EXCEEDED",
        "message": "You have exceeded the rate limit of 100 requests per minute."
    }
}
```

### Transaction Examples

**Points Transaction (Referral Reward):**
```json
{
    "transaction_type": "referral_reward",
    "amount": null,
    "points": 50,
    "payment_method": "referral_reward"
}
```

**Cash Transaction (Deposit):**
```json
{
    "transaction_type": "deposit",
    "amount": "100.50",
    "points": null,
    "payment_method": "bank"
}
```

**Mixed Transaction (Activity Reward with Cash Bonus):**
```json
{
    "transaction_type": "activity_reward",
    "amount": "5.00",
    "points": 25,
    "payment_method": "system"
}
```

### 3. Get Transaction Details
**GET** `/wallet/transactions/<transaction_id>/`
**Authentication Required:** Yes

Retrieves detailed information about a specific transaction by its ID.

**Path Parameters:**
- `transaction_id` - UUID of the transaction

**Success Response (200):**
```json
{
    "success": true,
    "message": "Transaction details retrieved successfully",
    "transaction": {
        "transaction_id": "e665132e-d834-45c2-90be-c4a7fd6d0d34",
        "wallet_id": "9a3f7748-18cf-4a40-bf09-23185b3baeeb",
        "user_name": "Test User",
        "user_email": "test@example.com",
        "transaction_type": "deposit",
        "transaction_type_display": "Deposit",
        "amount": "1000.00",
        "points": null,
        "currency": "NGN",
        "description": "Initial deposit",
        "reference": "WWE665132E",
        "payment_method": "bank",
        "payment_method_display": "Bank Transfer",
        "status": "success",
        "status_display": "Success",
        "metadata": null,
        "created_at": "2025-09-30T12:35:28.618290Z"
    }
}
```

**Error Response - Transaction Not Found (500):**
```json
{
    "success": false,
    "message": "An error occurred while retrieving the transaction",
    "error": {
        "code": "SERVER_ERROR",
        "message": "Error retrieving transaction {transaction_id} for user {email}: No WalletTransaction matches the given query."
    }
}
```

**Note:** Transactions belonging to other users will return a 500 error (transaction not found for current user).

**Example Usage:**
```bash
# Get specific transaction details
curl -X GET https://wasteworth-backend-django.onrender.com/api/v1/wallet/transactions/e665132e-d834-45c2-90be-c4a7fd6d0d34/ \
  -H "Authorization: Bearer YOUR_ACCESS_TOKEN"
```

### 4. Get Redemption Options
**GET** `/wallet/redemption-options/`
**Authentication Required:** Yes

Retrieves available options for redeeming eco-points.

**Response (200):**
```json
[
    {
        "redemption_type": "airtime",
        "points": 100
    },
    {
        "redemption_type": "voucher",
        "points": 200
    }
]
```

### 4. Redeem Points
**POST** `/wallet/redeem/`
**Authentication Required:** Yes

Redeems eco-points for rewards (airtime or voucher).

**Request Body:**
```json
{
    "option": "airtime",
    "points": 100
}
```

**Validation Rules:**
- `option`: Must be one of: `airtime`, `voucher`
- `points`: Minimum 100 points required
- User must have sufficient points

**Success Response (201):**
```json
{
    "message": "Redeemed 100 points for airtime",
    "transaction_id": "b44e74df-548d-448e-b430-453105098461",
    "wallet": {
        "wallet_id": "9a3f7748-18cf-4a40-bf09-23185b3baeeb",
        "user_name": "Test User",
        "user_email": "test@example.com",
        "balance": "800.00",
        "currency": "NGN",
        "points": 55,
        "is_active": true,
        "created_at": "2025-09-30T12:34:28.155720Z",
        "updated_at": "2025-09-30T13:14:18.073028Z"
    }
}
```

**Error Response - Insufficient Points (400):**
```json
{
    "error": "Not enough points"
}
```

**Error Response - Below Minimum (400):**
```json
{
    "success": false,
    "message": "The provided data is invalid. Please check the details below.",
    "error": {
        "code": "VALIDATION_ERROR",
        "message": "The provided data is invalid. Please check the details below.",
        "details": {
            "points": ["Ensure this value is greater than or equal to 100."]
        }
    }
}
```

**Example Usage:**
```bash
# Get available redemption options
curl -X GET https://wasteworth-backend-django.onrender.com/api/v1/wallet/redemption-options/ \
  -H "Authorization: Bearer YOUR_ACCESS_TOKEN"

# Redeem 100 points for airtime
curl -X POST https://wasteworth-backend-django.onrender.com/api/v1/wallet/redeem/ \
  -H "Authorization: Bearer YOUR_ACCESS_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"option": "airtime", "points": 100}'
```

### Error Handling

All wallet endpoints follow the same error format:

**Validation Error (400):**
```json
{
    "success": false,
    "error": {
        "code": "VALIDATION_ERROR",
        "message": "The provided data is invalid. Please check the details below.",
        "details": {
            "transaction_type": ["Points transactions must use one of: referral_reward, activity_reward, redeem"]
        }
    }
}
```

**Wallet Not Found (404):**
```json
{
    "success": false,
    "error": {
        "code": "NOT_FOUND",
        "message": "Wallet not found for authenticated user.",
        "details": {
            "wallet": ["No wallet associated with your account."]
        }
    }
}
```

---

## 🎁 Referral System

### Overview
The referral system rewards users for inviting others to join the platform. Users can share either referral codes or referral links.

### How It Works

**1. Every user gets:**
- A unique `referral_code` (e.g., `ABC123DE`)
- A shareable `referral_link` (e.g., `https://wasteworth.com/signup?ref=ABC123DE`)

**2. Sharing Options:**

**Option A: Share Referral Link (Recommended)**
```
User shares: https://wasteworth.com/signup?ref=ABC123DE
New user clicks link → Automatically applies referral during signup
```

**Option B: Share Referral Code (Backward Compatible)**
```
User shares code: "ABC123DE"
New user manually enters code in signup form
```

**3. Reward Structure:**
- **On Signup**: Referrer gets **100 points** immediately when referee verifies their account
- **On First Transaction**: Referrer gets **BONUS 100 points** when referee completes their first transaction
- **Total Potential**: **200 points per successful referral**

### Getting Your Referral Link

**Request:**
```bash
# For disposers
GET /api/v1/users/disposer-dashboard/
Authorization: Bearer YOUR_ACCESS_TOKEN

# For recyclers
GET /api/v1/users/recycler-dashboard/
Authorization: Bearer YOUR_ACCESS_TOKEN
```

**Response:**
```json
{
    "id": "uuid",
    "name": "John Doe",
    "email": "john@example.com",
    "referral_code": "ABC123DE",
    "referral_link": "https://wasteworth.com/signup?ref=ABC123DE",
    ...
}
```

### Using a Referral Link (Frontend Implementation)

**Step 1: Extract Referral from URL**
```javascript
// User clicks: https://wasteworth.com/signup?ref=ABC123DE

const urlParams = new URLSearchParams(window.location.search);
const referralCode = urlParams.get('ref'); // "ABC123DE"
```

**Step 2: Include in Signup Request**
```javascript
POST /api/v1/users/signup/
{
    "name": "Jane Doe",
    "email": "jane@example.com",
    "password": "SecurePass123!",
    "confirm_password": "SecurePass123!",
    "phone": "+1234567890",
    "role": "disposer",
    "referred_by": "ABC123DE"  // ← Include extracted code
}
```

**Step 3: Automatic Reward Distribution**
- System finds referrer by code
- Creates referral record
- Awards 100 points to referrer immediately
- Tracks for future bonus (100 points on first transaction)

### Referral Field in Signup

**Field Name:** `referred_by` (optional)
**Format:** 8-character alphanumeric code
**Example:** `ABC123DE`

```json
{
    "name": "New User",
    "email": "newuser@example.com",
    "password": "StrongPass123!",
    "confirm_password": "StrongPass123!",
    "phone": "+1234567890",
    "role": "disposer",
    "referred_by": "ABC123DE"  // Optional referral code
}
```

### Referral Validation

**Valid Referral:**
```json
// Signup succeeds, referrer gets points
{
    "success": true,
    "message": "Account created successfully...",
    "user_id": "uuid",
    "email": "newuser@example.com"
}
```

**Invalid Referral Code:**
```json
// Signup still succeeds, but no referral reward given
// Invalid code is silently ignored (logged for monitoring)
{
    "success": true,
    "message": "Account created successfully...",
    "user_id": "uuid",
    "email": "newuser@example.com"
}
```

### Best Practices

**For Frontend Developers:**
1. Extract `ref` parameter from URL on signup page
2. Pre-fill or auto-include in signup form
3. Show user whose referral link they're using (optional UX enhancement)
4. Don't block signup if referral code is invalid

**For Users:**
1. Share referral link for easiest experience
2. Fallback to sharing code if link doesn't work
3. Track referrals via wallet transaction history (transaction type: `referral_reward`)

### Tracking Referrals

**Check Referral Rewards:**
```bash
GET /api/v1/wallet/transactions/
Authorization: Bearer YOUR_ACCESS_TOKEN
```

**Filter for Referral Rewards:**
```json
{
    "results": [
        {
            "transaction_type": "referral_reward",
            "points": 100,
            "description": "Referral reward: Jane Doe signed up using your code",
            "status": "success"
        },
        {
            "transaction_type": "referral_reward",
            "points": 100,
            "description": "Referral bonus: Jane Doe completed their first transaction",
            "status": "success"
        }
    ]
}
```

### Configuration

**Environment Variable:**
```bash
# Set your frontend URL for referral links
FRONTEND_URL=https://wasteworth.com
```

**Default Behavior:**
- Development: Uses first ALLOWED_HOST with `http://`
- Production: Uses first ALLOWED_HOST with `https://`
- Can be overridden via `FRONTEND_URL` environment variable

---

## 📧 Contact Us Endpoint

### Overview
The Contact Us endpoint allows users (both authenticated and unauthenticated) to send messages to the WasteWorth support team. When a message is submitted, the system automatically sends two emails:
1. **Admin Notification** - Notifies the support team at info@wasteworth.com
2. **Auto-Reply** - Confirms receipt to the user

### Submit Contact Message

**POST** `/contact/`
**Authentication Required:** No (publicly accessible)

Accepts contact form submissions and sends automated emails.

**Request Body:**
```json
{
    "first_name": "Jane",
    "last_name": "Doe",
    "email": "jane@example.com",
    "message": "I'd love to know more about your recycling services.",
    "heard_about": "Instagram"
}
```

**Field Requirements:**
- `first_name` (required) - User's first name
- `last_name` (optional) - User's last name
- `email` (required) - Valid email address
- `message` (required) - Minimum 10 characters
- `heard_about` (optional) - How they heard about WasteWorth

**Success Response (201):**
```json
{
    "id": 1,
    "first_name": "Jane",
    "last_name": "Doe",
    "email": "jane@example.com",
    "message": "I'd love to know more about your recycling services.",
    "heard_about": "Instagram",
    "created_at": "2025-10-07T13:25:43Z"
}
```

**Validation Error Response (400):**
```json
{
    "first_name": ["First name is required."],
    "email": ["Email address is required."],
    "message": ["Message must be at least 10 characters long."]
}
```

### Email Notifications

**Admin Email (to info@wasteworth.com):**
```
Subject: New Contact Message from Jane Doe

You have received a new contact form submission.

From: Jane Doe
Email: jane@example.com
Heard about us: Instagram

Message:
I'd love to know more about your recycling services.

---
This is an automated notification from WasteWorth Contact Form.
```

**Auto-Reply Email (to user):**
```
Subject: Thanks for contacting WasteWorth

Hello Jane,

Thank you for reaching out to WasteWorth. We've received your message and our support team will get back to you shortly.

Your message:
"I'd love to know more about your recycling services."

We typically respond within 24-48 hours during business days.

Best regards,
The WasteWorth Team

---
This is an automated confirmation email. Please do not reply to this email.
```

### Example Usage

**JavaScript/Fetch:**
```javascript
fetch('https://wasteworth-backend-django.onrender.com/api/v1/contact/', {
    method: 'POST',
    headers: {
        'Content-Type': 'application/json'
    },
    body: JSON.stringify({
        first_name: 'Jane',
        last_name: 'Doe',
        email: 'jane@example.com',
        message: "I'd love to know more about your recycling services.",
        heard_about: 'Instagram'
    })
})
.then(response => response.json())
.then(data => {
    console.log('Message sent successfully:', data);
})
.catch(error => {
    console.error('Error sending message:', error);
});
```

**cURL:**
```bash
curl -X POST https://wasteworth-backend-django.onrender.com/api/v1/contact/ \
  -H "Content-Type: application/json" \
  -d '{
    "first_name": "Jane",
    "last_name": "Doe",
    "email": "jane@example.com",
    "message": "I would love to know more about your recycling services.",
    "heard_about": "Instagram"
  }'
```

### Error Handling

**Missing Required Fields:**
```json
{
    "first_name": ["This field is required."],
    "message": ["This field is required."]
}
```

**Invalid Email:**
```json
{
    "email": ["Enter a valid email address."]
}
```

**Message Too Short:**
```json
{
    "message": ["Message must be at least 10 characters long."]
}
```

### Email Configuration

Emails are sent using Django's email backend configured in settings. If email is not configured or fails, the endpoint will still return success (emails fail silently) to ensure the contact form doesn't break if email service is down.

**Email Settings Required:**
- `DEFAULT_FROM_EMAIL` - Sender email address
- `EMAIL_HOST` - SMTP server
- `EMAIL_PORT` - SMTP port
- `EMAIL_HOST_USER` - SMTP username
- `EMAIL_HOST_PASSWORD` - SMTP password

### Notes

- ✅ No authentication required - publicly accessible
- ✅ Automatic email notifications to admin
- ✅ Automatic confirmation email to user
- ✅ Emails fail silently to prevent errors
- ✅ Data stored in database for admin review
- ✅ Accessible via Django admin panel

---

## 💳 Payment & Escrow System

### Overview
The payment system uses **Paystack** for secure payment processing and an **escrow mechanism** to protect both disposers and recyclers. Funds are held in escrow until both parties confirm the transaction.

### Payment Flow States

```
pending → payment_initiated → locked → item_released → confirmed → released
```

| State | Description | Who Can Trigger |
|-------|-------------|-----------------|
| `pending` | Listing available for purchase | N/A |
| `payment_initiated` | Recycler started payment | Recycler (Initialize) |
| `locked` | Payment verified, escrow locked | System (Verify) |
| `item_released` | Disposer confirmed item handover | Disposer (Confirm Release) |
| `confirmed` | Recycler confirmed receipt | Recycler (Confirm Receipt) |
| `released` | Escrow released, rewards distributed | System (Auto) |

---

### 1. Initialize Payment

**POST** `/payments/initialize/`
**Authentication Required:** Yes (Recycler)
**Rate Limit:** 10 requests per hour per user

Recycler initiates payment for a listing. This creates a Paystack checkout session.

**Request Body:**
```json
{
    "listing_id": "550e8400-e29b-41d4-a716-446655440000",
    "amount": "255.00"  // Optional: for verification
}
```

**Success Response (200):**
```json
{
    "success": true,
    "message": "Payment initialized successfully. Redirect user to authorization_url.",
    "payment_id": "abc-123-def-456",
    "authorization_url": "https://checkout.paystack.com/xxxxx",
    "access_code": "xxxxx",
    "reference": "WW-A1B2C3D4E5F6",
    "amount": "255.00",
    "currency": "NGN"
}
```

**Frontend Action:**
Redirect user to `authorization_url` to complete payment on Paystack.

**Error Responses:**

**Own Listing (400):**
```json
{
    "success": false,
    "message": "You cannot purchase your own listing"
}
```

**Listing Not Available (400):**
```json
{
    "success": false,
    "message": "Listing is not available for purchase (status: completed)"
}
```

**Amount Mismatch (400):**
```json
{
    "success": false,
    "message": "Amount mismatch. Expected: 255.00, Provided: 200.00"
}
```

---

### 2. Verify Payment

**GET** `/payments/verify/?reference=WW-xxxxx`
**Authentication Required:** Yes (Recycler)

After Paystack redirects back, verify the payment was successful.

**Query Parameters:**
- `reference` (required) - Payment reference from initialize

**Success Response (200):**
```json
{
    "success": true,
    "message": "Payment verified successfully. Escrow locked. Contact the disposer to collect the item.",
    "payment": {
        "payment_id": "abc-123-def-456",
        "status": "success",
        "amount": "255.00",
        "reference": "WW-A1B2C3D4E5F6",
        "paid_at": "2025-10-09T10:30:00Z",
        "payment_method": "card"
    },
    "marketplace_listing": {
        "id": "marketplace-listing-uuid",
        "escrow_status": "locked",
        "listing_id": "listing-uuid",
        "disposer": {
            "name": "John Doe",
            "phone": "+1234567890",
            "location": {
                "lat": 40.7128,
                "lng": -74.0060
            }
        }
    }
}
```

**What Happens:**
- ✅ Payment verified with Paystack
- ✅ Escrow locked (funds held securely)
- ✅ Listing status updated to "accepted"
- ✅ Disposer contact info provided for collection

**Error Response - Already Verified (200):**
```json
{
    "success": true,
    "message": "Payment already verified",
    "payment": {...},
    "marketplace_listing": {...}
}
```

**Error Response - Verification Failed (400):**
```json
{
    "success": false,
    "message": "Payment verification failed",
    "error": "Payment was not successful"
}
```

---

### 3. Confirm Item Released (Disposer)

**POST** `/payments/confirm-release/`
**Authentication Required:** Yes (Disposer)

Disposer confirms they have handed over the item to the recycler.

**Request Body:**
```json
{
    "marketplace_listing_id": "marketplace-listing-uuid"
}
```

**Success Response (200):**
```json
{
    "success": true,
    "message": "Item release confirmed. The recycler has been notified to confirm receipt.",
    "marketplace_listing": {
        "id": "marketplace-listing-uuid",
        "escrow_status": "item_released",
        "released_at": "2025-10-09T11:00:00Z"
    }
}
```

**What Happens:**
- ✅ Marketplace listing status → `item_released`
- ✅ Listing status → `in-progress`
- ✅ Recycler notified to confirm receipt

**Error Response - Wrong Status (400):**
```json
{
    "success": false,
    "message": "Cannot confirm release. Current status: pending"
}
```

**Error Response - Not Disposer (403):**
```json
{
    "success": false,
    "message": "Only the disposer can confirm item release"
}
```

---

### 4. Confirm Item Received (Recycler) - Triggers Escrow Release

**POST** `/payments/confirm-receipt/`
**Authentication Required:** Yes (Recycler)

Recycler confirms they have received the item. **This triggers escrow release and reward distribution.**

**Request Body:**
```json
{
    "marketplace_listing_id": "marketplace-listing-uuid"
}
```

**Success Response (200):**
```json
{
    "success": true,
    "message": "Item receipt confirmed! Escrow released, rewards distributed, and payout initiated.",
    "marketplace_listing": {
        "id": "marketplace-listing-uuid",
        "escrow_status": "released",
        "released_at": "2025-10-09T12:00:00Z"
    },
    "rewards": {
        "disposer_points": 50,
        "recycler_points": 25,
        "disposer_referrer_bonus": 100,
        "recycler_referrer_bonus": 50,
        "errors": []
    },
    "payout": {
        "payout_id": "payout-uuid",
        "amount": "255.00",
        "status": "pending",
        "error": null
    }
}
```

**What Happens:**
- ✅ Escrow released (funds no longer held)
- ✅ Disposer payout initiated to bank account
- ✅ Points awarded to disposer (50) and recycler (25)
- ✅ Bonus points to referrers (if applicable)
- ✅ Listing status → `completed`
- ✅ Marketplace status → `released`

**Error Response - Wrong Status (400):**
```json
{
    "success": false,
    "message": "Cannot confirm receipt. Current status: locked"
}
```

**Error Response - Not Recycler (403):**
```json
{
    "success": false,
    "message": "Only the recycler can confirm item receipt"
}
```

---

### 5. Paystack Webhook (Internal)

**POST** `/payments/webhook/`
**Authentication:** Paystack Signature Verification
**CSRF:** Exempt

Handles Paystack webhook events for payment and payout updates.

**Events Handled:**
- `charge.success` - Payment completed
- `transfer.success` - Payout completed
- `transfer.failed` - Payout failed
- `transfer.reversed` - Payout reversed

**Response (200):**
```json
{
    "success": true,
    "message": "Webhook processed successfully"
}
```

---

## 💰 Payment Flow Examples

### Complete End-to-End Flow

```javascript
// ============ STEP 1: RECYCLER INITIALIZES PAYMENT ============
const initResponse = await fetch('/api/v1/payments/initialize/', {
    method: 'POST',
    headers: {
        'Authorization': `Bearer ${recyclerToken}`,
        'Content-Type': 'application/json'
    },
    body: JSON.stringify({
        listing_id: 'listing-uuid',
        amount: '255.00'
    })
});

const initData = await initResponse.json();
// {
//   authorization_url: "https://checkout.paystack.com/xxxxx",
//   reference: "WW-A1B2C3D4E5F6"
// }

// ============ STEP 2: REDIRECT TO PAYSTACK ============
window.location.href = initData.authorization_url;
// User completes payment on Paystack, then redirected back

// ============ STEP 3: VERIFY PAYMENT ============
const verifyResponse = await fetch(`/api/v1/payments/verify/?reference=${initData.reference}`, {
    headers: {
        'Authorization': `Bearer ${recyclerToken}`
    }
});

const verifyData = await verifyResponse.json();
// {
//   success: true,
//   payment: { status: "success" },
//   marketplace_listing: { escrow_status: "locked" },
//   disposer: { name: "John", phone: "+123..." }
// }

// Escrow is now LOCKED. Show disposer contact info.
// Recycler contacts disposer to arrange collection.

// ============ STEP 4: DISPOSER CONFIRMS ITEM HANDOVER ============
const releaseResponse = await fetch('/api/v1/payments/confirm-release/', {
    method: 'POST',
    headers: {
        'Authorization': `Bearer ${disposerToken}`,
        'Content-Type': 'application/json'
    },
    body: JSON.stringify({
        marketplace_listing_id: verifyData.marketplace_listing.id
    })
});

const releaseData = await releaseResponse.json();
// {
//   success: true,
//   marketplace_listing: { escrow_status: "item_released" }
// }

// ============ STEP 5: RECYCLER CONFIRMS RECEIPT (TRIGGERS RELEASE) ============
const receiptResponse = await fetch('/api/v1/payments/confirm-receipt/', {
    method: 'POST',
    headers: {
        'Authorization': `Bearer ${recyclerToken}`,
        'Content-Type': 'application/json'
    },
    body: JSON.stringify({
        marketplace_listing_id: verifyData.marketplace_listing.id
    })
});

const receiptData = await receiptResponse.json();
// {
//   success: true,
//   marketplace_listing: { escrow_status: "released" },
//   rewards: { disposer_points: 50, recycler_points: 25 },
//   payout: { payout_id: "...", amount: "255.00", status: "pending" }
// }

// Transaction complete!
// - Disposer gets payout to bank account
// - Both parties receive eco-points
// - Referrers get bonus points
```

---

### Error Handling

```javascript
try {
    const response = await fetch('/api/v1/payments/initialize/', {
        method: 'POST',
        headers: {
            'Authorization': `Bearer ${token}`,
            'Content-Type': 'application/json'
        },
        body: JSON.stringify({
            listing_id: 'some-uuid',
            amount: '255.00'
        })
    });

    const data = await response.json();

    if (!data.success) {
        // Handle specific errors
        if (data.message.includes('own listing')) {
            alert('You cannot purchase your own listing');
        } else if (data.message.includes('not available')) {
            alert('This listing is no longer available');
        } else {
            alert(data.message);
        }
        return;
    }

    // Success - redirect to Paystack
    window.location.href = data.authorization_url;

} catch (error) {
    console.error('Payment error:', error);
    alert('An error occurred. Please try again.');
}
```

---

### Testing the Payment Flow

**Prerequisites:**
- Paystack test API keys configured
- Test card: `4084084084084081`
- Test CVV: `408`
- Test expiry: Any future date

**Test Sequence:**
```bash
# 1. Initialize payment (as recycler)
curl -X POST http://localhost:8000/api/v1/payments/initialize/ \
  -H "Authorization: Bearer RECYCLER_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"listing_id":"listing-uuid","amount":"255.00"}'

# 2. Complete payment on Paystack (use test card above)

# 3. Verify payment
curl http://localhost:8000/api/v1/payments/verify/?reference=WW-xxxxx \
  -H "Authorization: Bearer RECYCLER_TOKEN"

# 4. Confirm item release (as disposer)
curl -X POST http://localhost:8000/api/v1/payments/confirm-release/ \
  -H "Authorization: Bearer DISPOSER_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"marketplace_listing_id":"marketplace-uuid"}'

# 5. Confirm item receipt (as recycler)
curl -X POST http://localhost:8000/api/v1/payments/confirm-receipt/ \
  -H "Authorization: Bearer RECYCLER_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"marketplace_listing_id":"marketplace-uuid"}'
```

---

### Payment Security Features

✅ **Escrow Protection**
- Funds held securely until both parties confirm
- Automatic dispute resolution after timeout
- Refund capability for failed transactions

✅ **Paystack Integration**
- PCI-DSS compliant payment processing
- Webhook signature verification
- Automatic reconciliation

✅ **Fraud Prevention**
- Users cannot purchase own listings
- Amount verification before processing
- Transaction status validation

✅ **Audit Trail**
- All state changes timestamped
- Payment provider responses logged
- Webhook events recorded

---

## 🔍 Status Codes

| Code | Description |
|------|-------------|
| 200 | Success |
| 201 | Created (signup) |
| 400 | Bad Request (validation errors) |
| 401 | Unauthorized (missing/invalid token) |
| 403 | Forbidden (insufficient permissions) |
| 404 | Not Found (user/resource not found) |
| 500 | Internal Server Error |

---

## 🧪 Testing

Test the API endpoints:
```bash
# Test signup with validation errors
curl -X POST https://wasteworth-backend-django.onrender.com/api/v1/users/signup/ \
  -H "Content-Type: application/json" \
  -d '{"name": "", "email": "invalid-email", "password": "weak", "role": "invalid"}'

# Test login with wrong password
curl -X POST https://wasteworth-backend-django.onrender.com/api/v1/users/login/ \
  -H "Content-Type: application/json" \
  -d '{"email": "test@example.com", "password": "wrongpassword"}'

# Test dashboard without authentication
curl -X GET https://wasteworth-backend-django.onrender.com/api/v1/users/disposer-dashboard/
curl -X GET https://wasteworth-backend-django.onrender.com/api/v1/users/recycler-dashboard/

# Test wallet endpoints with authentication
curl -X GET https://wasteworth-backend-django.onrender.com/api/v1/wallet/balance/ \
  -H "Authorization: Bearer YOUR_ACCESS_TOKEN"

# Test wallet transactions with pagination
curl -X GET "https://wasteworth-backend-django.onrender.com/api/v1/wallet/transactions/?page=1&page_size=20" \
  -H "Authorization: Bearer YOUR_ACCESS_TOKEN"

```

---

**🎉 Your comprehensive API with wallet management and OTP authentication is ready for production use!**

**Key Features:**
✅ Consistent error response format across all endpoints
✅ OTP integration for sensitive operations
✅ Two-step profile updates for security
✅ Wallet management with points and cash
✅ Transaction filtering and listing
✅ Points-first eco-system with referral rewards
✅ **Referral links** - Easy sharing with automatic code application
✅ **Backward compatible** - Supports both referral links and manual codes
✅ **Contact form** - Public endpoint with automated email notifications
✅ Production-ready with proper authentication and validation