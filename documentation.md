# Wasteworth API Documentation

## Authentication

The API uses JWT (JSON Web Token) authentication.  
Include the access token in the Authorization header:


---
Authorization: Bearer <access_token>

## Endpoints

### 1. Forgot Password

**POST /users/forgotPassword/**

Initiates password reset for a user.  
Returns a generic message and a JWT reset token if the email exists.

**Request Body:**
```json
{
    "email": "user@example.com"
}

Success Response (200):
{
    "detail": "If the email exists, password reset instructions will be sent.",
    "reset_token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..."
}

Error Response (400):
{
    "email": ["Enter a valid email address."]
}


Frontend Action:

The forgot password endpoint sends an OTP to the user's email.
Use POST /users/resetPassword/ with the user's email, OTP, and new password to complete the reset.


2. Reset Password
POST /users/resetPassword/

Resets the user's password using OTP verification.

Request Body:
{
    "email": "user@example.com",
    "otp": "123456",
    "new_password": "newsecurepassword123",
    "confirm_password": "newsecurepassword123"
}

Success Response (200):
{
    "success": true,
    "message": "Password reset successfully."
}

Error Responses:

##Invalid OTP:
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

##User not found:
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

##Passwords don't match:
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


3. Update Password
PATCH /users/updatePassword/

Authentication Required: Yes
Allows a logged-in user to change their password.

Request Body:
{
    "old_password": "currentpassword",
    "new_password": "newsecurepassword123",
    "new_password_confirm": "newsecurepassword123"
}

##Success Response (200):
{
    "detail": "Password updated successfully."
}

Error Responses:

##Old password incorrect:
{
    "old_password": ["Old password is incorrect."]
}

##New passwords don't match:
{
    "new_password": "New passwords didn't match."
}

##Authentication required:
{
    "detail": "Authentication credentials were not provided."
}

Token Management
Access Token

Lifetime: 60 minutes
Usage: Include in Authorization header for authenticated requests
Format: Authorization: Bearer <access_token>
Refresh Token

Lifetime: 7 days
Usage: Use to obtain new access tokens when they expire
Security: Tokens are blacklisted after rotation
Token Refresh To refresh an expired access token, use the DRF Simple JWT token refresh endpoint:

##POST /auth/token/refresh/
{
    "refresh": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..."
}
