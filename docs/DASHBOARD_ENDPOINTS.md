# Dashboard Endpoints - Direct Database Access

## Overview

This document describes the new dashboard endpoints that use **direct database queries** instead of Node.js API calls. Both endpoints query the shared PostgreSQL database directly using Django ORM.

## Endpoints

### 1. Disposer Dashboard

**Endpoint:** `GET /api/v1/users/disposer-dashboard/`

**Authentication:** Required (JWT Bearer token)

**Description:** Returns disposer-specific statistics and recent activity.

#### Response Structure

```json
{
  "user": {
    "id": "uuid",
    "name": "John Doe",
    "email": "john@example.com",
    "phone": "+234123456789",
    "role": "disposer",
    "address_location": {...},
    "wallet_balance": "1250.50",
    "points": 150,
    "referral_code": "ABC123DE",
    "referral_link": "https://wasteworth.com/signup?ref=ABC123DE",
    "created_at": "2025-01-15T10:30:00Z"
  },
  "stats": {
    "total_listings": 12,
    "sold_listings": 7,
    "recent_posts": [
      {
        "id": "uuid",
        "title": "Plastic Bottles",
        "waste_type": "plastic",
        "quantity": 15.5,
        "status": "completed",
        "reward_estimate": "450.00",
        "image_url": "https://...",
        "created_at": "2025-10-05T14:20:00Z"
      },
      ...
    ]
  }
}
```

#### Data Sources

| Field | Source Table | Managed By | Query Description |
|-------|-------------|-----------|-------------------|
| `user.*` | `users` | Django | User profile data via `UserProfileSerializer` |
| `total_listings` | `listings` | Node.js | Count of all listings created by this disposer |
| `sold_listings` | `marketplace_listings` | Node.js | Count of listings with `escrow_status` = 'released' or 'completed' |
| `recent_posts` | `listings` | Node.js | 5 most recent listings by this disposer, ordered by `created_at` DESC |

#### Example Request

```bash
curl -X GET \
  https://api.wasteworth.com/api/v1/users/disposer-dashboard/ \
  -H "Authorization: Bearer YOUR_JWT_TOKEN"
```

---

### 2. Recycler Dashboard

**Endpoint:** `GET /api/v1/users/recycler-dashboard/`

**Authentication:** Required (JWT Bearer token)

**Description:** Returns recycler-specific metrics and system-wide active listings.

#### Response Structure

```json
{
  "user": {
    "id": "uuid",
    "name": "Jane Smith",
    "email": "jane@example.com",
    "phone": "+234987654321",
    "role": "recycler",
    "address_location": {...},
    "wallet_balance": "3500.00",
    "points": 450,
    "referral_code": "XYZ789FG",
    "referral_link": "https://wasteworth.com/signup?ref=XYZ789FG",
    "created_at": "2025-02-10T09:15:00Z"
  },
  "stats": {
    "total_kg_collected": 127.5,
    "total_points": 450,
    "recent_posts": [
      {
        "id": "uuid",
        "title": "Glass Bottles",
        "waste_type": "glass",
        "quantity": 25.0,
        "status": "pending",
        "reward_estimate": "750.00",
        "image_url": "https://...",
        "pickup_location": {...},
        "created_at": "2025-10-07T11:45:00Z"
      },
      ...
    ]
  }
}
```

#### Data Sources

| Field | Source Table | Managed By | Query Description |
|-------|-------------|-----------|-------------------|
| `user.*` | `users` | Django | User profile data via `UserProfileSerializer` |
| `total_kg_collected` | `marketplace_listings` + `listings` | Node.js | Sum of `quantity` from all completed marketplace purchases by this recycler |
| `total_points` | `wallets` | Django | Current points balance from user's wallet |
| `recent_posts` | `listings` | Node.js | 5 most recent system-wide listings with status 'pending' or 'accepted' |

#### Example Request

```bash
curl -X GET \
  https://api.wasteworth.com/api/v1/users/recycler-dashboard/ \
  -H "Authorization: Bearer YOUR_JWT_TOKEN"
```

---

## Database Schema Reference

### Tables Used

#### Django-Managed Tables

- **`users`** - User accounts (name, email, role, etc.)
- **`wallets`** - Wallet balances and points

#### Node.js-Managed Tables

- **`listings`** - Disposer posts (waste items for sale)
- **`marketplace_listings`** - Recycler purchases and escrow status

### Key Relationships

```
users (Django)
  ↓ (one-to-one)
wallets (Django)

users (Django)
  ↓ (one-to-many)
listings (Node)
  ↓ (one-to-many)
marketplace_listings (Node)
```

---

## Implementation Details

### Disposer Dashboard Query Logic

```python
# 1. Total listings by disposer
total_listings = Listing.objects.filter(user_id=user).count()

# 2. Sold listings (completed marketplace transactions)
sold_listings = MarketplaceListing.objects.filter(
    listing_id__user_id=user,
    escrow_status__in=['released', 'completed']
).count()

# 3. Recent 5 posts by disposer
recent_posts = Listing.objects.filter(
    user_id=user
).order_by('-created_at')[:5]
```

### Recycler Dashboard Query Logic

```python
# 1. Total kg collected by recycler
total_kg_collected = MarketplaceListing.objects.filter(
    recycler_id=user,
    escrow_status__in=['released', 'completed']
).aggregate(total_kg=Sum('listing_id__quantity'))['total_kg'] or 0

# 2. Total points from wallet
wallet = Wallet.objects.get(user=user)
total_points = wallet.points

# 3. Recent 5 system-wide active listings
recent_posts = Listing.objects.filter(
    status__in=['pending', 'accepted']
).order_by('-created_at')[:5]
```

---

## Error Handling

Both endpoints handle the following edge cases:

- **Missing wallet:** Returns `points: 0` and `wallet_balance: "0.00"` if wallet doesn't exist
- **No listings:** Returns empty arrays for `recent_posts`
- **No marketplace transactions:** Returns `0` for counts and sums

---

## Performance Considerations

### Optimizations

1. **Indexed queries:** All queries use indexed fields (`user_id`, `created_at`, `escrow_status`)
2. **Limited result sets:** Recent posts capped at 5 items
3. **Direct DB access:** No network calls to Node.js API
4. **Efficient aggregations:** Uses database-level `COUNT()` and `SUM()`

### Rate Limiting

Both endpoints are rate-limited to **30 requests per minute per user**.

---

## Migration Notes

### Breaking Changes

These endpoints replace the old combined dashboard logic:

- **Old approach:** API calls to Node.js service
- **New approach:** Direct database queries via Django ORM

### Backward Compatibility

The old endpoint `/api/v1/users/user-dashboard/` is maintained for backward compatibility and currently maps to the disposer dashboard.

---

## Testing

Run the test suite to validate queries:

```bash
python test_dashboards.py
```

Expected output:
```
[SUCCESS] Both dashboard endpoints are ready to use!

Endpoints:
  - GET /api/v1/users/disposer-dashboard/
  - GET /api/v1/users/recycler-dashboard/
```

---

## Example Responses

### Disposer Dashboard (Full Example)

```json
{
  "user": {
    "id": "a1b2c3d4-e5f6-7890-abcd-ef1234567890",
    "name": "John Disposer",
    "email": "john@example.com",
    "phone": "+2348012345678",
    "role": "disposer",
    "address_location": {
      "address": "123 Main St",
      "city": "Lagos",
      "state": "Lagos",
      "coordinates": {
        "lat": 6.5244,
        "lng": 3.3792
      }
    },
    "wallet_balance": "1250.50",
    "points": 150,
    "referral_code": "JOHN8765",
    "referral_link": "https://wasteworth.com/signup?ref=JOHN8765",
    "created_at": "2025-01-15T10:30:00Z"
  },
  "stats": {
    "total_listings": 12,
    "sold_listings": 7,
    "recent_posts": [
      {
        "id": "b2c3d4e5-f6a7-8901-bcde-f12345678901",
        "title": "Plastic Bottles - 15kg",
        "waste_type": "plastic",
        "quantity": 15.0,
        "status": "completed",
        "reward_estimate": "450.00",
        "image_url": "https://res.cloudinary.com/wasteworth/image/upload/v1234567890/listings/plastic.jpg",
        "created_at": "2025-10-05T14:20:00Z"
      },
      {
        "id": "c3d4e5f6-a7b8-9012-cdef-123456789012",
        "title": "Glass Containers",
        "waste_type": "glass",
        "quantity": 8.5,
        "status": "pending",
        "reward_estimate": "200.00",
        "image_url": "https://res.cloudinary.com/wasteworth/image/upload/v1234567890/listings/glass.jpg",
        "created_at": "2025-10-03T09:15:00Z"
      }
    ]
  }
}
```

### Recycler Dashboard (Full Example)

```json
{
  "user": {
    "id": "d4e5f6a7-b8c9-0123-defg-234567890123",
    "name": "Jane Recycler",
    "email": "jane@example.com",
    "phone": "+2348087654321",
    "role": "recycler",
    "address_location": {
      "address": "456 Market Rd",
      "city": "Abuja",
      "state": "FCT",
      "coordinates": {
        "lat": 9.0765,
        "lng": 7.3986
      }
    },
    "wallet_balance": "3500.00",
    "points": 450,
    "referral_code": "JANE5432",
    "referral_link": "https://wasteworth.com/signup?ref=JANE5432",
    "created_at": "2025-02-10T09:15:00Z"
  },
  "stats": {
    "total_kg_collected": 127.5,
    "total_points": 450,
    "recent_posts": [
      {
        "id": "e5f6a7b8-c9d0-1234-efgh-345678901234",
        "title": "Paper Waste - 30kg",
        "waste_type": "paper",
        "quantity": 30.0,
        "status": "pending",
        "reward_estimate": "600.00",
        "image_url": "https://res.cloudinary.com/wasteworth/image/upload/v1234567890/listings/paper.jpg",
        "pickup_location": {
          "address": "789 Office Park",
          "city": "Lagos",
          "coordinates": {
            "lat": 6.4541,
            "lng": 3.3947
          }
        },
        "created_at": "2025-10-07T11:45:00Z"
      },
      {
        "id": "f6a7b8c9-d0e1-2345-fghi-456789012345",
        "title": "Aluminum Cans",
        "waste_type": "plastic",
        "quantity": 12.0,
        "status": "accepted",
        "reward_estimate": "360.00",
        "image_url": "https://res.cloudinary.com/wasteworth/image/upload/v1234567890/listings/aluminum.jpg",
        "pickup_location": {
          "address": "321 Restaurant St",
          "city": "Port Harcourt",
          "coordinates": {
            "lat": 4.8156,
            "lng": 7.0498
          }
        },
        "created_at": "2025-10-07T08:30:00Z"
      }
    ]
  }
}
```

---

## Support

For questions or issues, contact the backend team or create an issue in the repository.
