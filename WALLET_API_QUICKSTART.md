# Wallet API Endpoints - Quickstart Guide

This guide provides examples of how to use the Wasteworth wallet API endpoints using curl commands. You can use these examples to test the API directly from the command line or adapt them for use in your application.

## Prerequisites

1. You must have a valid JWT token from logging in to the Wasteworth platform.
2. Replace `{YOUR_TOKEN}` with your actual JWT token in all examples.
3. Replace `{BASE_URL}` with your API base URL (e.g., `http://localhost:8000`).

## Authentication

### Login to Get JWT Token

```bash
curl -X POST \
  {BASE_URL}/api/v1/users/login/ \
  -H 'Content-Type: application/json' \
  -d '{
    "email": "your_email@example.com",
    "password": "your_password"
  }'
```

Response:
```json
{
  "access": "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9...",
  "refresh": "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9...",
  "user": {
    "id": "3fa85f64-5717-4562-b3fc-2c963f66afa6",
    "email": "your_email@example.com",
    "name": "Your Name"
  }
}
```

## Wallet Endpoints

### Get Wallet Details

```bash
curl -X GET \
  {BASE_URL}/api/v1/wallet/ \
  -H 'Authorization: Bearer {YOUR_TOKEN}'
```

### Get Wallet Balance

```bash
curl -X GET \
  {BASE_URL}/api/v1/wallet/balance/ \
  -H 'Authorization: Bearer {YOUR_TOKEN}'
```

### Get Transaction History

```bash
curl -X GET \
  '{BASE_URL}/api/v1/wallet/transactions/?page=1&page_size=10' \
  -H 'Authorization: Bearer {YOUR_TOKEN}'
```

### Filter Transactions by Type

```bash
curl -X GET \
  '{BASE_URL}/api/v1/wallet/transactions/?transaction_type=deposit' \
  -H 'Authorization: Bearer {YOUR_TOKEN}'
```

### Get Wallet Statistics

```bash
curl -X GET \
  {BASE_URL}/api/v1/wallet/stats/ \
  -H 'Authorization: Bearer {YOUR_TOKEN}'
```

## Transaction Operations

### Create Deposit

```bash
curl -X POST \
  {BASE_URL}/api/v1/wallet/deposit/ \
  -H 'Authorization: Bearer {YOUR_TOKEN}' \
  -H 'Content-Type: application/json' \
  -d '{
    "amount": "500.00",
    "payment_method": "bank",
    "description": "Adding funds to wallet"
  }'
```

### Create Withdrawal

```bash
curl -X POST \
  {BASE_URL}/api/v1/wallet/withdraw/ \
  -H 'Authorization: Bearer {YOUR_TOKEN}' \
  -H 'Content-Type: application/json' \
  -d '{
    "amount": "200.00",
    "payment_method": "bank",
    "description": "Withdrawal to bank account",
    "bank_account": "0123456789",
    "bank_name": "User Bank",
    "account_name": "User Name"
  }'
```

### Redeem Points

```bash
curl -X POST \
  {BASE_URL}/api/v1/wallet/redeem-points/ \
  -H 'Authorization: Bearer {YOUR_TOKEN}' \
  -H 'Content-Type: application/json' \
  -d '{
    "points": 100
  }'
```

## Error Handling Examples

### Insufficient Funds Error

```
HTTP/1.1 400 Bad Request
Content-Type: application/json

{
  "error": "insufficient_funds",
  "message": "Insufficient funds to complete this transaction."
}
```

### Invalid Amount Error

```
HTTP/1.1 400 Bad Request
Content-Type: application/json

{
  "error": "invalid_amount",
  "message": "Amount must be greater than zero."
}
```

### Authentication Error

```
HTTP/1.1 401 Unauthorized
Content-Type: application/json

{
  "error": "authentication_error",
  "message": "Authentication credentials were not provided or are invalid."
}
```

## Testing with Postman

For easier testing, import the included Postman collection:

1. Open Postman
2. Click "Import" button
3. Select the `wasteworth_wallet_api.postman_collection.json` file
4. Set up environment variables:
   - `base_url`: Your API base URL
   - `jwt_token`: Your authentication token
5. Run the collection to test all endpoints