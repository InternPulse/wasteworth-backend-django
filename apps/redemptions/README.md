
# Points Redemption Module Documentation

## Overview

The **Redemptions module** allows users to redeem their accumulated points for **airtime** or **vouchers**. It is built on top of the `Wallet` and `WalletTransaction` models and exposes three main API endpoints.

---

## 🔧 Models

### `Wallet`

* Stores the user’s balance and eco-points.

| Field      | Type      | Description                 |
| ---------- | --------- | --------------------------- |
| wallet_id  | UUID (PK) | Unique ID for the wallet    |
| user       | OneToOne  | Linked to `AUTH_USER_MODEL` |
| balance    | Decimal   | Cash balance                |
| points     | Integer   | Earned points               |
| updated_at | DateTime  | Last update                 |

---

### `WalletTransaction`

* Stores all transactions related to the wallet (credits, debits, redemptions, etc.).

| Field            | Type       | Description                      |
| ---------------- | ---------- | -------------------------------- |
| transaction_id   | UUID (PK)  | Unique ID for transaction        |
| user             | ForeignKey | Owner of transaction             |
| transaction_type | CharField  | e.g. `redeem`, `credit`, `debit` |
| amount           | Decimal    | Cash amount (if applicable)      |
| points           | Integer    | Redeemed points                  |
| payment_method   | CharField  | `airtime`, `voucher`, etc.       |
| status           | CharField  | `pending`, `success`, `failed`   |
| created_at       | DateTime   | Timestamp                        |

---

## 🖥️ API Endpoints

### 1. **Get Redemption Options**

**GET** `/api/v1/points/redemption-options/`

Returns available redemption types and minimum points required.

**Response Example:**

```json
[
  { "redemption_type": "airtime", "points": 100 },
  { "redemption_type": "voucher", "points": 200 }
]
```

---

### 2. **Redeem Points**

**POST** `/api/v1/points/redeem/`

Redeems user points for airtime or vouchers.

**Request Body Example:**

```json
{
  "option": "airtime",
  "points": 150
}
```

**Response Example:**

```json
{
  "message": "Redeemed 150 points for airtime",
  "transaction_id": "f3a7d92b-1c42-4e56-9c47-8b24b4f1234d",
  "wallet": {
    "wallet_id": "d1e29f6f-4ac7-4b33-9221-9fdf19b89234",
    "points": 850,
    "balance": "0.00",
    "updated_at": "2025-09-29T12:00:00Z"
  }
}
```

**Validation Rules:**

* Minimum **100 points** required.
* User must have enough points in wallet.

---

### 3. **Redemption History**

**GET** `/api/v1/points/redemption-history/`

Returns a list of past redemption transactions for the authenticated user.

**Response Example:**

```json
[
  {
    "transaction_id": "f3a7d92b-1c42-4e56-9c47-8b24b4f1234d",
    "transaction_type": "redeem",
    "points": 150,
    "status": "success",
    "created_at": "2025-09-29T12:00:00Z"
  }
]
```

---

## 🔐 Authentication

* All endpoints require **JWT Authentication** (`Bearer <token>`).
* A wallet must exist for the user before redeeming.

---

## ⚠️ Error Responses

| Status | Error Example                                                   |
| ------ | --------------------------------------------------------------- |
| 400    | `{ "error": "Not enough points to redeem" }`                    |
| 401    | `{ "detail": "Authentication credentials were not provided." }` |
| 404    | `{ "error": "Wallet not found" }`                               |


