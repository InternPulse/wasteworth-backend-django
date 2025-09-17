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

## Error Handling

### HTTP Status Codes
- `200`: Success
- `201`: Created
- `400`: Bad Request (validation errors)
- `401`: Unauthorized (authentication required)
- `403`: Forbidden (insufficient permissions)
- `404`: Not Found
- `500`: Internal Server Error

### Error Response Format
```json
{
    "field_name": ["Error message for this field"],
    "non_field_errors": ["General error messages"],
    "error": "Simple error message"
}
```

## CORS Configuration
**Development:** Automatically accepts requests from common development ports
**Production:** Configure `CORS_ALLOWED_ORIGINS` environment variable with your frontend domains

## Development Setup

### Prerequisites
- Python 3.13+
- PostgreSQL (or SQLite for testing)

### Installation
1. Clone the repository
2. Install dependencies: `pip install -r requirements.txt`
3. Run migrations: `python manage.py migrate`
4. Start development server: `python manage.py runserver`

### Testing Endpoints
You can test the endpoints using curl, Postman, or any HTTP client:

```bash
# Signup
curl -X POST http://localhost:8000/api/v1/users/signup/ \
  -H "Content-Type: application/json" \
  -d '{"email":"test@example.com","password":"testpass123","confirm_password":"testpass123","role":"disposer"}'

# Login
curl -X POST http://localhost:8000/api/v1/users/login/ \
  -H "Content-Type: application/json" \
  -d '{"email":"test@example.com","password":"testpass123"}'

# Logout (requires access token)
curl -X POST http://localhost:8000/api/v1/users/logout/ \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer <access_token>" \
  -d '{"refresh_token":"<refresh_token>"}'
```

## Frontend Integration Tips

1. **Store Tokens Securely:** Store tokens in httpOnly cookies or secure storage
2. **Handle Token Expiry:** Implement automatic token refresh logic
3. **Error Handling:** Handle different error responses appropriately
4. **CSRF Protection:** Not required for API endpoints (using JWT)
5. **Content-Type:** Always set `Content-Type: application/json` for POST requests

## User Roles
- `disposer`: Users who dispose waste (default)
- `recycler`: Users who recycle waste
- `admin`: System administrators

## Data Models

### User Model Fields
```json
{
    "userId": "UUID (Primary Key)",
    "name": "string (optional)",
    "email": "string (unique, required for signup)",
    "phone": "string (optional, unique)",
    "role": "enum: 'disposer' | 'recycler' | 'admin'",
    "location": "object: { lat: float, lng: float } (optional)",
    "walletBalance": "decimal (default: 0.00)",
    "referralCode": "string (auto-generated)",
    "referredBy": "string (referral code of inviter, optional)",
    "createdAt": "datetime",
    "updatedAt": "datetime"
}
```

### Listing Model Fields
```json
{
    "listingId": "UUID (Primary Key)",
    "userId": "UUID (Foreign Key to User)",
    "collectorId": "UUID (Foreign Key to User, optional)",
    "wasteType": "enum: 'plastic' | 'glass' | 'paper'",
    "quantity": "float",
    "status": "enum: 'pending' | 'accepted' | 'in-progress' | 'completed' | 'cancelled'",
    "rewardEstimate": "decimal",
    "finalReward": "decimal (optional)",
    "pickupLocation": "object: { lat: float, lng: float }",
    "createdAt": "datetime",
    "updatedAt": "datetime"
}
```

### Notification Model Fields
```json
{
    "notificationId": "UUID (Primary Key)",
    "userId": "UUID (Foreign Key to User)",
    "type": "enum: 'pickup' | 'reward' | 'marketplace' | 'general'",
    "message": "string",
    "isRead": "boolean (default: false)",
    "createdAt": "datetime"
}
```

### Wallet Model Fields
```json
{
    "walletId": "UUID (Primary Key)",
    "userId": "UUID (One-to-One with User)",
    "balance": "decimal (default: 0.00)",
    "updatedAt": "datetime"
}
```

### Transaction Model Fields
```json
{
    "transactionId": "UUID (Primary Key)",
    "userId": "UUID (Foreign Key to User)",
    "transactionType": "enum: 'credit' | 'debit' | 'payout' | 'referral'",
    "amount": "decimal",
    "paymentMethod": "enum: 'bank' | 'mobileMoney' | 'airtime'",
    "status": "enum: 'pending' | 'success' | 'failed'",
    "createdAt": "datetime"
}
```

## Production Deployment

### Environment Variables
Copy `.env.example` to `.env` and configure:

**Required for Production:**
```bash
SECRET_KEY=your-production-secret-key
DEBUG=False
ALLOWED_HOSTS=yourdomain.com,www.yourdomain.com,api.yourdomain.com
DATABASE_NAME=wasteworth_prod
DATABASE_USER=your-db-user
DATABASE_PASSWORD=your-db-password
DATABASE_HOST=your-db-host
DATABASE_PORT=5432
SSL_MODE=require
CORS_ALLOWED_ORIGINS=https://yourdomain.com,https://www.yourdomain.com
```

### Security Features
- **HTTPS Enforcement:** Automatic redirect to HTTPS in production
- **HSTS:** HTTP Strict Transport Security enabled
- **Secure Cookies:** Session and CSRF cookies marked as secure
- **Content Security:** XSS protection and content type sniffing protection
- **SSL Database Connection:** Required in production

### Deployment Checklist
1. ✅ Set all environment variables
2. ✅ Configure database with SSL
3. ✅ Update CORS origins to match frontend domains
4. ✅ Run migrations: `python manage.py migrate`
5. ✅ Collect static files: `python manage.py collectstatic`
6. ✅ Create superuser: `python manage.py createsuperuser`

## Security Notes
- Passwords are hashed using Django's built-in password hashing
- JWT tokens include expiration times
- Refresh tokens are blacklisted after use (when rotation is enabled)
- Email validation is performed on signup
- Production environment enforces HTTPS and secure cookies