# Wasteworth Wallet API Documentation

## Overview

The Wallet module provides functionality for managing user wallets, transactions, and balance management within the Wasteworth platform. This module enables users to manage their finances, receive payments for waste collection, and track transaction history.

## Table of Contents

- [Models](#models)
- [API Endpoints](#api-endpoints)
- [Authentication](#authentication)
- [Common Use Cases](#common-use-cases)
- [Error Handling](#error-handling)
- [Postman Collection](#postman-collection)

## Models

### Wallet

The Wallet model represents a user's financial account within the platform.

| Field       | Type        | Description                           |
|-------------|-------------|---------------------------------------|
| wallet_id   | UUID        | Primary key and unique identifier     |
| user        | ForeignKey  | One-to-one relationship with User     |
| balance     | Decimal     | Current cash balance (default: 0.00)  |
| currency    | CharField   | Currency code (default: NGN)          |
| points      | Integer     | Eco-points earned from activities     |
| is_active   | Boolean     | Wallet status (default: True)         |
| created_at  | DateTime    | Timestamp when wallet was created     |
| updated_at  | DateTime    | Timestamp of last update              |

### WalletTransaction

The WalletTransaction model records all financial movements within a wallet.

| Field            | Type        | Description                           |
|------------------|-------------|---------------------------------------|
| transaction_id   | UUID        | Primary key and unique identifier     |
| wallet           | ForeignKey  | Associated wallet                     |
| user             | ForeignKey  | User who performed the transaction    |
| transaction_type | CharField   | Type of transaction (see choices)     |
| amount           | Decimal     | Transaction amount in currency        |
| points           | Integer     | Points involved (for point transactions) |
| currency         | CharField   | Currency code (default: NGN)          |
| description      | CharField   | Transaction description               |
| payment_method   | CharField   | Method of payment (see choices)       |
| reference        | CharField   | Unique transaction reference          |
| status           | CharField   | Transaction status                    |
| created_at       | DateTime    | Timestamp when transaction occurred   |
| updated_at       | DateTime    | Timestamp of last update              |

**Transaction Types:**
- `credit`: Adding funds to wallet
- `debit`: Removing funds from wallet
- `payout`: Payment to external account
- `referral_reward`: Bonus from referrals
- `activity_reward`: Reward for platform activities
- `redeem`: Converting points to currency
- `deposit`: User adding funds
- `withdrawal`: User withdrawing funds

**Payment Methods:**
- `bank`: Bank transfer
- `mobileMoney`: Mobile money services
- `airtime`: Airtime credit
- `voucher`: Voucher code
- `system`: System-generated credit
- `card`: Card payment

**Status Options:**
- `pending`: Transaction initiated but not completed
- `processing`: Transaction in progress
- `success`: Transaction completed successfully
- `failed`: Transaction failed
- `cancelled`: Transaction cancelled

## API Endpoints

### Base URL

All API endpoints are prefixed with `/api/v1/wallet/`.

### Authentication

All wallet endpoints require authentication with JWT. Include the token in the Authorization header:

```
Authorization: Bearer <your_jwt_token>
```

### Endpoints Reference

#### Get User Wallet

Returns the wallet details for the authenticated user.

- **URL**: `/api/v1/wallet/`
- **Method**: `GET`
- **Auth required**: Yes
- **Permissions**: Owner only

**Response:**

```json
{
  "wallet_id": "3b9b4d4a-187e-4393-9121-b0b2539d1d52",
  "balance": "700.00",
  "currency": "NGN",
  "points": 0,
  "is_active": true,
  "created_at": "2025-09-25T14:30:45.123456Z",
  "updated_at": "2025-09-26T10:15:30.654321Z"
}
```

#### Get Wallet Balance

Returns only the balance information for quick access.

- **URL**: `/api/v1/wallet/balance/`
- **Method**: `GET`
- **Auth required**: Yes
- **Permissions**: Owner only

**Response:**

```json
{
  "balance": "700.00",
  "currency": "NGN",
  "points": 0
}
```

#### Get Transaction History

Returns a paginated list of transactions for the authenticated user's wallet.

- **URL**: `/api/v1/wallet/transactions/`
- **Method**: `GET`
- **Auth required**: Yes
- **Permissions**: Owner only
- **Query Parameters**:
  - `page`: Page number (default: 1)
  - `page_size`: Number of transactions per page (default: 10)
  - `transaction_type`: Filter by transaction type
  - `status`: Filter by transaction status

**Response:**

```json
{
  "count": 4,
  "next": null,
  "previous": null,
  "results": [
    {
      "transaction_id": "7f9c6b5a-432d-4e87-9f01-1234abcd5678",
      "transaction_type": "deposit",
      "amount": "500.00",
      "currency": "NGN",
      "description": "Initial deposit",
      "payment_method": "bank",
      "reference": "DEP12345678",
      "status": "success",
      "created_at": "2025-09-25T15:30:45.123456Z"
    },
    {
      "transaction_id": "8e7d5c4b-321e-4f56-8e12-9876dcba5432",
      "transaction_type": "deposit",
      "amount": "250.00",
      "currency": "NGN",
      "description": "Second deposit",
      "payment_method": "bank",
      "reference": "DEP87654321",
      "status": "success",
      "created_at": "2025-09-25T16:45:30.654321Z"
    }
    // Additional transactions...
  ]
}
```

#### Get Transaction Detail

Returns details of a specific transaction.

- **URL**: `/api/v1/wallet/transactions/<transaction_id>/`
- **Method**: `GET`
- **Auth required**: Yes
- **Permissions**: Owner only

**Response:**

```json
{
  "transaction_id": "7f9c6b5a-432d-4e87-9f01-1234abcd5678",
  "wallet_id": "3b9b4d4a-187e-4393-9121-b0b2539d1d52",
  "transaction_type": "deposit",
  "amount": "500.00",
  "currency": "NGN",
  "description": "Initial deposit",
  "payment_method": "bank",
  "reference": "DEP12345678",
  "status": "success",
  "created_at": "2025-09-25T15:30:45.123456Z",
  "updated_at": "2025-09-25T15:30:45.123456Z"
}
```

#### Create Deposit

Initiates a deposit transaction to the user's wallet.

- **URL**: `/api/v1/wallet/deposit/`
- **Method**: `POST`
- **Auth required**: Yes
- **Permissions**: Owner only

**Request Body:**

```json
{
  "amount": "500.00",
  "payment_method": "bank",
  "description": "Adding funds to wallet"
}
```

**Response:**

```json
{
  "transaction_id": "9a8b7c6d-543f-4e12-8d90-1234abcdef56",
  "amount": "500.00",
  "status": "pending",
  "reference": "DEP98765432",
  "created_at": "2025-09-26T11:30:45.123456Z",
  "payment_instructions": {
    "account_number": "0123456789",
    "bank_name": "Wasteworth Bank",
    "account_name": "Wasteworth Deposits",
    "reference": "DEP98765432"
  }
}
```

#### Create Withdrawal

Initiates a withdrawal from the user's wallet.

- **URL**: `/api/v1/wallet/withdraw/`
- **Method**: `POST`
- **Auth required**: Yes
- **Permissions**: Owner only

**Request Body:**

```json
{
  "amount": "200.00",
  "payment_method": "bank",
  "description": "Withdrawal to bank account",
  "bank_account": "0123456789",
  "bank_name": "User Bank",
  "account_name": "User Name"
}
```

**Response:**

```json
{
  "transaction_id": "1a2b3c4d-654e-4f32-9g78-5678abcdef12",
  "amount": "200.00",
  "status": "processing",
  "reference": "WTH12345678",
  "created_at": "2025-09-26T12:45:30.654321Z",
  "estimated_completion": "1-2 business days"
}
```

#### Get Wallet Statistics

Returns summarized statistics about the wallet activity.

- **URL**: `/api/v1/wallet/stats/`
- **Method**: `GET`
- **Auth required**: Yes
- **Permissions**: Owner only

**Response:**

```json
{
  "total_deposits": "750.00",
  "total_withdrawals": "150.00",
  "referral_earnings": "100.00",
  "points_earned": 0,
  "points_redeemed": 0,
  "transaction_count": {
    "total": 4,
    "deposits": 2,
    "withdrawals": 1,
    "rewards": 1
  },
  "currency": "NGN"
}
```

#### Redeem Points

Converts points into wallet currency balance.

- **URL**: `/api/v1/wallet/redeem-points/`
- **Method**: `POST`
- **Auth required**: Yes
- **Permissions**: Owner only

**Request Body:**

```json
{
  "points": 100
}
```

**Response:**

```json
{
  "transaction_id": "5e6f7g8h-987i-6j54-3k21-9876lmnopq43",
  "points_redeemed": 100,
  "amount_credited": "50.00",
  "currency": "NGN",
  "status": "success",
  "reference": "RDM12345678",
  "created_at": "2025-09-26T14:15:30.654321Z"
}
```

## Error Handling

Wallet API uses standard HTTP status codes and consistent error response format:

### Common Error Responses

#### Authentication Error (401)

```json
{
  "error": "authentication_error",
  "message": "Authentication credentials were not provided or are invalid."
}
```

#### Permission Error (403)

```json
{
  "error": "permission_denied",
  "message": "You do not have permission to perform this action."
}
```

#### Insufficient Funds (400)

```json
{
  "error": "insufficient_funds",
  "message": "Insufficient funds to complete this transaction."
}
```

#### Invalid Amount (400)

```json
{
  "error": "invalid_amount",
  "message": "Amount must be greater than zero."
}
```

## Postman Collection

### Setup Instructions

1. Download the Postman collection file (wasteworth_wallet_api.json)
2. Import into Postman
3. Setup environment variables:
   - `base_url`: Your API base URL (e.g., `http://localhost:8000`)
   - `jwt_token`: Your authentication token

### Collection Structure

```
Wasteworth Wallet API
├── Authentication
│   ├── Login
│   └── Refresh Token
├── Wallet Management
│   ├── Get Wallet
│   ├── Get Wallet Balance
│   └── Get Wallet Statistics
├── Transactions
│   ├── Get Transaction History
│   ├── Get Transaction Detail
│   ├── Create Deposit
│   └── Create Withdrawal
└── Points Management
    ├── Redeem Points
    └── Get Points History
```

### Postman Examples

#### Get Wallet

```
GET {{base_url}}/api/v1/wallet/
Headers:
  Authorization: Bearer {{jwt_token}}
```

#### Create Deposit

```
POST {{base_url}}/api/v1/wallet/deposit/
Headers:
  Authorization: Bearer {{jwt_token}}
  Content-Type: application/json
Body:
{
  "amount": "500.00",
  "payment_method": "bank",
  "description": "Adding funds to wallet"
}
```

## Common Use Cases

### Wallet Creation Flow

1. User registration automatically triggers wallet creation
2. New wallet is initialized with zero balance
3. User can then make deposits to fund their wallet

### Transaction Processing

1. User initiates transaction (deposit, withdrawal)
2. System creates a transaction record with "pending" status
3. External payment processing occurs (if applicable)
4. System updates transaction status and wallet balance

### Wallet Balance Updates

The wallet balance is updated through transactions:

- **Increases**: deposits, credits, referral rewards, activity rewards, point redemptions
- **Decreases**: withdrawals, debits, payouts

### Points Earning & Redemption

1. User performs activities (referrals, recycling)
2. System awards points to wallet
3. User can redeem points for wallet balance

## Integration with Other Modules

The wallet module integrates with:

1. **User Module**: Each user has one wallet
2. **Marketplace Module**: Payments for waste collection
3. **Referral Module**: Rewards for successful referrals

## Database Considerations

- Transactions use atomic operations to ensure data consistency
- Wallet balance is a calculated field based on transaction history
- Indexes are created on frequently queried fields for performance