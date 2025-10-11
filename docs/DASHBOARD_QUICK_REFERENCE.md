# Dashboard Endpoints - Quick Reference

## 🚀 Quick Start

### Disposer Dashboard
```bash
GET /api/v1/users/disposer-dashboard/
Authorization: Bearer <JWT_TOKEN>
```

**Returns:**
- User profile
- Total listings created
- Sold listings count
- Recent 5 posts

---

### Recycler Dashboard
```bash
GET /api/v1/users/recycler-dashboard/
Authorization: Bearer <JWT_TOKEN>
```

**Returns:**
- User profile
- Total kg collected
- Total points
- System-wide recent 5 posts

---

## 📊 Response Structures

### Disposer Response
```json
{
  "user": { /* UserProfileSerializer */ },
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
      }
    ]
  }
}
```

### Recycler Response
```json
{
  "user": { /* UserProfileSerializer */ },
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
      }
    ]
  }
}
```

---

## 🗂️ Data Sources

### Disposer Dashboard
| Field | Source | Query |
|-------|--------|-------|
| `user` | User table | Via UserProfileSerializer |
| `total_listings` | Listing table | COUNT where user_id = user |
| `sold_listings` | MarketplaceListing table | COUNT where escrow_status = 'released'/'completed' |
| `recent_posts` | Listing table | Last 5 listings by user |

### Recycler Dashboard
| Field | Source | Query |
|-------|--------|-------|
| `user` | User table | Via UserProfileSerializer |
| `total_kg_collected` | MarketplaceListing + Listing | SUM(quantity) where recycler_id = user |
| `total_points` | Wallet table | points field |
| `recent_posts` | Listing table | Last 5 system-wide pending/accepted listings |

---

## 🔍 Key Differences

| Feature | Disposer | Recycler |
|---------|----------|----------|
| **Recent Posts** | User's own listings | System-wide listings |
| **Listings Count** | ✅ Yes | ❌ No |
| **Sold Count** | ✅ Yes | ❌ No |
| **Kg Collected** | ❌ No | ✅ Yes |
| **Points** | ✅ Yes (from user profile) | ✅ Yes (from stats) |

---

## ⚡ Performance

- **Rate Limit:** 30 requests/minute per user
- **Response Time:** < 100ms (direct DB queries)
- **No External Calls:** All data from PostgreSQL
- **Indexed Queries:** Optimized with DB indexes

---

## 🧪 Testing

```bash
# Run test suite
python test_dashboards.py

# Expected output
[SUCCESS] Both dashboard endpoints are ready to use!
```

---

## 📝 Implementation Files

- **Views:** [apps/users/views.py](../apps/users/views.py)
  - `DisposerDashboardView` (line 271)
  - `RecyclerDashboardView` (line 361)
- **URLs:** [apps/users/urls.py](../apps/users/urls.py) (lines 27-28)
- **Tests:** [test_dashboards.py](../test_dashboards.py)
- **Full Docs:** [DASHBOARD_ENDPOINTS.md](DASHBOARD_ENDPOINTS.md)

---

## 🔧 Usage Examples

### cURL

```bash
# Disposer Dashboard
curl -X GET \
  https://api.wasteworth.com/api/v1/users/disposer-dashboard/ \
  -H "Authorization: Bearer YOUR_JWT_TOKEN"

# Recycler Dashboard
curl -X GET \
  https://api.wasteworth.com/api/v1/users/recycler-dashboard/ \
  -H "Authorization: Bearer YOUR_JWT_TOKEN"
```

### Python Requests

```python
import requests

headers = {"Authorization": f"Bearer {jwt_token}"}

# Disposer
response = requests.get(
    "https://api.wasteworth.com/api/v1/users/disposer-dashboard/",
    headers=headers
)
data = response.json()

# Recycler
response = requests.get(
    "https://api.wasteworth.com/api/v1/users/recycler-dashboard/",
    headers=headers
)
data = response.json()
```

### JavaScript Fetch

```javascript
// Disposer
const disposerData = await fetch('/api/v1/users/disposer-dashboard/', {
  headers: {
    'Authorization': `Bearer ${jwtToken}`
  }
}).then(res => res.json());

// Recycler
const recyclerData = await fetch('/api/v1/users/recycler-dashboard/', {
  headers: {
    'Authorization': `Bearer ${jwtToken}`
  }
}).then(res => res.json());
```

---

## ⚠️ Error Handling

Both endpoints handle edge cases gracefully:

- **No wallet:** Returns `points: 0` and `wallet_balance: "0.00"`
- **No listings:** Returns empty `recent_posts: []`
- **No transactions:** Returns `0` for counts/sums

---

## 🎯 Status

**Implementation:** ✅ Complete
**Testing:** ✅ Passed
**Documentation:** ✅ Complete
**Production Ready:** ✅ Yes

---

For detailed documentation, see [DASHBOARD_ENDPOINTS.md](DASHBOARD_ENDPOINTS.md)
