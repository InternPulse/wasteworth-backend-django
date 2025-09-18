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

Use the reset_token to build a password reset link, e.g.
https://your-frontend.com/reset-password/<reset_token>
Send this link to the user via email.


2. Reset Password
PATCH /users/resetPassword/<resetToken>/

Resets the user's password using the JWT reset token.

Request Body:
{
    "password": "newsecurepassword123",
    "password_confirm": "newsecurepassword123"
}

Success Response (200):
{
    "detail": "Password has been reset successfully."
}

Error Responses:

##Expired token:
{
    "detail": "Reset token has expired."
}

##Invalid token:
{
    "detail": "Invalid reset token."
}

##User not found:
{
    "detail": "User not found."
}

##Passwords don't match:
{
    "password": "Password fields didn't match."
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
