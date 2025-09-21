# Wasteworth API Documentation

## Base URL
**Development:**
```
http://localhost:8000/api/v1/
```

**Production:**
```
https://your-domain.com/api/v1/
```

## Authentication
The API uses JWT (JSON Web Token) authentication. Include the access token in the Authorization header:
```
Authorization: Bearer <access_token>
```

## Quick Start Guide

### 1. Sign Up → Verify → Login
```bash
# Step 1: Create account (sends OTP to email)
POST /users/signup/

# Step 2: Verify OTP to complete registration
POST /otp/verify/?action=signup

# Step 3: Login normally (no OTP needed)
POST /users/login/
```

### 2. Reset Password
```bash
# Step 1: Request password reset (sends OTP)
POST /users/forgotPassword/

# Step 2: Verify OTP and set new password
POST /otp/verify/?action=reset
```

---

## 📋 All Endpoints

### 🔐 Authentication Endpoints

#### 1. User Signup
**POST** `/users/signup/`

Creates a new **unverified** user account and sends OTP to email.

**Request Body:**
```json
{
    "email": "user@example.com",
    "password": "StrongPass123!",
    "confirm_password": "StrongPass123!",
    "role": "disposer"
}
```

**Valid Roles:** `disposer`, `recycler`, `admin`

**Success Response (201):**
```json
{
    "success": true,
    "message": "Account created successfully. Please verify your email with the OTP sent to complete registration.",
    "user_id": "550e8400-e29b-41d4-a716-446655440000",
    "email": "user@example.com",
    "is_verified": false,
    "otp_sent": true,
    "next_step": "Verify OTP using POST /api/v1/otp/verify/?action=signup to get access tokens"
}
```

**Error Response (400):**
```json
{
    "success": false,
    "errors": {
        "email": ["An account with this email already exists. Try logging in instead."],
        "password": ["Password must contain at least one uppercase letter"],
        "confirm_password": ["Passwords do not match. Please ensure both password fields are identical."]
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
        "id": "550e8400-e29b-41d4-a716-446655440000",
        "name": "",
        "email": "user@example.com",
        "phone": null,
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
        "id": "550e8400-e29b-41d4-a716-446655440000",
        "name": "",
        "email": "user@example.com",
        "phone": null,
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
    "non_field_errors": ["No account found with this email address. Please check your email or sign up."]
}
```

#### 4. User Logout
**POST** `/users/logout/`
**Authentication Required:** Yes

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

---

### 🔑 Password Management

#### 5. Forgot Password (Request Reset)
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
    "next_step": "Use POST /api/v1/otp/verify/?action=reset with email, otp, and new_password"
}
```

#### 6. Reset Password (Verify OTP + Set New Password)
**POST** `/otp/verify/?action=reset`

Verifies OTP and resets password in one step.

**Request Body:**
```json
{
    "email_or_phone": "user@example.com",
    "otp": "123456",
    "new_password": "NewStrongPass123!"
}
```

**Success Response (200):**
```json
{
    "success": true,
    "message": "Password reset successful",
    "user": {
        "id": "550e8400-e29b-41d4-a716-446655440000",
        "name": "",
        "email": "user@example.com",
        "phone": null,
        "role": "disposer",
        "address_location": null,
        "wallet_balance": "0.00",
        "referral_code": "ABC123DEF",
        "created_at": "2025-01-15T10:30:00Z"
    }
}
```

#### 7. Update Password (Two-Step Process)
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
    "message": "OTP sent to your email. Please provide OTP and new_password to complete password update.",
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

#### 8. Send OTP
**POST** `/otp/send/`

Manually send OTP for any purpose.

**Request Body:**
```json
{
    "email_or_phone": "user@example.com",
    "purpose": "signup"
}
```

**Valid Purposes:** `signup`, `reset`, `login`

**Success Response (200):**
```json
{
    "success": true,
    "message": "OTP sent successfully",
    "otp_id": "abc-123-def-456",
    "expires_at": "2025-01-15T10:40:00Z"
}
```

#### 9. Resend OTP
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
    "message": "New OTP sent successfully",
    "otp_id": "xyz-789-abc-123"
}
```

#### 10. Request Password Reset (Alternative)
**POST** `/otp/request-password-reset/`

Alternative endpoint for password reset.

**Request Body:**
```json
{
    "email_or_phone": "user@example.com"
}
```

**Success Response (200):**
```json
{
    "success": true,
    "message": "OTP for password reset sent"
}
```

---

## 🔒 Security Features

### OTP Security
- **6-digit numeric codes**
- **10-minute expiration**
- **Single-use only** (cannot be reused)
- **Purpose validation** (signup OTP ≠ reset OTP)
- **Previous OTP invalidation** on resend
- **Secure hashing** in database storage

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

## ⚠️ Error Responses

### Common Error Formats

**Validation Errors (400):**
```json
{
    "success": false,
    "errors": {
        "email": ["This field is required."],
        "password": ["Password must be at least 8 characters long"]
    }
}
```

**Authentication Errors (401):**
```json
{
    "success": false,
    "error": {
        "code": "TOKEN_REQUIRED",
        "message": "Token is required",
        "details": {
            "refresh_token": ["Refresh token is required to log out securely."]
        }
    }
}
```

**OTP Errors (400):**
```json
{
    "success": false,
    "errors": {
        "otp": ["Invalid OTP"]
    }
}
```

**Server Errors (500):**
```json
{
    "success": false,
    "error": "Failed to send password reset instructions. Please try again."
}
```

---

## 🧪 Testing

Use the provided test runner:
```bash
python run_auth_tests.py
```

Or test individual endpoints:
```bash
# Test OTP functionality
python manage.py test apps.otp -v 2

# Test authentication flows
python manage.py test apps.users.test_otp_integration -v 2
```

---

## 📱 Usage Examples

### Complete Signup Flow
```javascript
// 1. Sign up
const signupResponse = await fetch('/api/v1/users/signup/', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({
        email: 'user@example.com',
        password: 'StrongPass123!',
        confirm_password: 'StrongPass123!',
        role: 'disposer'
    })
});

// 2. Verify OTP (user enters OTP from email)
const verifyResponse = await fetch('/api/v1/otp/verify/?action=signup', {
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
await fetch('/api/v1/users/forgotPassword/', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({
        email: 'user@example.com'
    })
});

// 2. Reset with OTP
await fetch('/api/v1/otp/verify/?action=reset', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({
        email_or_phone: 'user@example.com',
        otp: '123456',
        new_password: 'NewPassword123!'
    })
});
```

### Authenticated Request
```javascript
const response = await fetch('/api/v1/users/updatePassword/', {
    method: 'PATCH',
    headers: {
        'Content-Type': 'application/json',
        'Authorization': `Bearer ${accessToken}`
    },
    body: JSON.stringify({
        old_password: 'CurrentPassword123!'
    })
});
```

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

**🎉 Your OTP-based authentication system is ready for production use!**