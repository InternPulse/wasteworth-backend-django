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

### 3. Update Profile (Sensitive Fields)
```bash
# Step 1: Request OTP for email/phone/role changes
PATCH /users/update-user/ (with sensitive field)

# Step 2: Verify OTP and complete update
PATCH /users/update-user/ (with same data + OTP)
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

#### 5. User Dashboard
**GET** `/users/user-dashboard/`
**Authentication Required:** Yes

Gets authenticated user's profile information.

**Success Response (200):**
```json
{
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
    "created_at": "2025-01-15T10:30:00Z"
}
```

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

#### 6. Update User Profile (Two-Step Process)
**PATCH** `/users/update-user/`
**Authentication Required:** Yes

Updates user profile. **Sensitive fields** (email, phone, role) require OTP verification.

**Sensitive Fields:** `email`, `phone`, `role`
**Non-Sensitive Fields:** `name`, `address_location`

**Step 1 - Update Non-Sensitive Fields (Direct):**
```json
{
    "name": "Updated Name",
    "address_location": {
        "lat": 40.7128,
        "lng": -74.0060
    }
}
```

**Step 1 Response (200):**
```json
{
    "success": true,
    "message": "Profile updated successfully",
    "data": {
        "id": "e4e0dbb2-9384-4278-b84b-e5679f2664e7",
        "name": "Updated Name",
        "email": "user@example.com",
        "phone": "+1234567890",
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

**Step 1 - Update Sensitive Fields (Sends OTP):**
```json
{
    "email": "newemail@example.com"
}
```

**Step 1 Response (200):**
```json
{
    "success": true,
    "message": "Profile update requires verification. OTP sent to your email.",
    "otp_id": "abc-123-def-456",
    "next_step": "Provide the same data along with the OTP to complete the update"
}
```

**Step 2 - Verify OTP + Complete Update:**
```json
{
    "email": "newemail@example.com",
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
        "email": "newemail@example.com",
        "phone": "+1234567890",
        "role": "disposer",
        "address_location": null,
        "wallet_balance": "150.00",
        "referral_code": "ABC123DEF",
        "created_at": "2025-01-15T10:30:00Z"
    }
}
```

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
    "message": "OTP sent successfully",
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
    "message": "New OTP sent successfully",
    "otp_id": "xyz-789-abc-123"
}
```

#### 12. Request Password Reset (OTP Method)
**POST** `/otp/request-password-reset/`

Alternative method to request password reset OTP. More direct than `/users/forgotPassword/`.

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

**Note:** This endpoint provides the same functionality as `/users/forgotPassword/` but is more direct and part of the OTP module.

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
// 1. Update non-sensitive field (direct)
await fetch('https://wasteworth-backend-django.onrender.com/api/v1/users/update-user/', {
    method: 'PATCH',
    headers: {
        'Content-Type': 'application/json',
        'Authorization': `Bearer ${accessToken}`
    },
    body: JSON.stringify({
        name: 'Updated Name'
    })
});

// 2. Update sensitive field (requires OTP)
// Step 1: Request OTP
await fetch('https://wasteworth-backend-django.onrender.com/api/v1/users/update-user/', {
    method: 'PATCH',
    headers: {
        'Content-Type': 'application/json',
        'Authorization': `Bearer ${accessToken}`
    },
    body: JSON.stringify({
        email: 'newemail@example.com'
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
        email: 'newemail@example.com',
        otp: '123456'
    })
});
```

### Authenticated Request
```javascript
const response = await fetch('https://wasteworth-backend-django.onrender.com/api/v1/users/user-dashboard/', {
    method: 'GET',
    headers: {
        'Content-Type': 'application/json',
        'Authorization': `Bearer ${accessToken}`
    }
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
curl -X GET https://wasteworth-backend-django.onrender.com/api/v1/users/user-dashboard/
```

---

**🎉 Your OTP-based authentication system with consistent error handling is ready for production use!**

**Key Features:**
✅ Consistent error response format across all endpoints
✅ OTP integration for sensitive operations
✅ Two-step profile updates for security
✅ Comprehensive validation with detailed error messages
✅ Production-ready with proper authentication