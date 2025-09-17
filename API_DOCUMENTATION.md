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

## Endpoints

### 1. User Signup
**POST** `/users/signup/`

Creates a new user account and returns JWT tokens.

**Request Body:**
```json
{
    "email": "user@example.com",
    "password": "securepassword123",
    "confirm_password": "securepassword123",
    "role": "disposer"
}
```

**Success Response (201):**
```json
{
    "message": "User created successfully",
    "user": {
        "userId": "550e8400-e29b-41d4-a716-446655440000",
        "name": null,
        "email": "user@example.com",
        "phone": null,
        "role": "disposer",
        "location": null,
        "walletBalance": "0.00",
        "referralCode": "DEF456ABC",
        "createdAt": "2025-01-15T10:30:00Z"
    },
    "tokens": {
        "refresh": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
        "access": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..."
    }
}
```

**Error Response (400):**
```json
{
    "email": ["Email already exists"],
    "password": ["This field may not be blank."],
    "non_field_errors": ["Passwords don't match"]
}
```

### 2. User Login
**POST** `/users/login/`

Authenticates a user and returns JWT tokens.

**Request Body:**
```json
{
    "email": "user@example.com",
    "password": "securepassword123"
}
```

**Success Response (200):**
```json
{
    "message": "Login successful",
    "user": {
        "userId": "550e8400-e29b-41d4-a716-446655440000",
        "name": null,
        "email": "user@example.com",
        "phone": null,
        "role": "disposer",
        "location": null,
        "walletBalance": "0.00",
        "referralCode": "DEF456ABC",
        "createdAt": "2025-01-15T10:30:00Z"
    },
    "tokens": {
        "refresh": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
        "access": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..."
    }
}
```

**Error Response (400):**
```json
{
    "non_field_errors": ["Invalid credentials"]
}
```

### 3. User Logout
**POST** `/users/logout/`

**Authentication Required:** Yes

Blacklists the refresh token to logout the user.

**Request Body:**
```json
{
    "refresh_token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..."
}
```

**Success Response (200):**
```json
{
    "message": "Logout successful"
}
```

**Error Responses:**
```json
// Missing refresh token (400)
{
    "error": "Refresh token required"
}

// Invalid token (400)
{
    "error": "Invalid token"
}

// Authentication required (401)
{
    "detail": "Authentication credentials were not provided."
}
```

## Token Management

### Access Token
- **Lifetime:** 60 minutes
- **Usage:** Include in Authorization header for authenticated requests
- **Format:** `Authorization: Bearer <access_token>`

### Refresh Token
- **Lifetime:** 7 days
- **Usage:** Use to obtain new access tokens when they expire
- **Security:** Tokens are blacklisted after rotation

### Token Refresh
To refresh an expired access token, use the DRF Simple JWT token refresh endpoint:

**POST** `/auth/token/refresh/`
```json
{
    "refresh": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..."
}
```

