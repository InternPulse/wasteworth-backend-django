# Integration Requirements for Complete Marketplace Flow

## Current Status

✅ **What's Working:**
- User signup and OTP verification
- Referral rewards on signup (100 points)
- Wallet balance tracking
- Activity reward distribution logic (tested manually)
- Listing creation in Node.js

✅ **What We Tested Successfully:**
- Set `escrow_status='released'` on MarketplaceListing
- Called `process_marketplace_rewards()` function
- Distributed rewards:
  - Disposer: +255 points (activity reward)
  - Recycler: +255 points (activity reward) + 100 points (first transaction bonus)

---

## What's Missing for Production

To make the marketplace transaction flow complete, you need to integrate Django's reward system with Node.js. Here are the required changes:

### 1. **Create Django Webhook Endpoint**

**File:** `apps/wallet/views.py`

Add a new view to handle marketplace transaction completion from Node.js:

```python
@api_view(['POST'])
@permission_classes([IsAuthenticated])  # Or use internal API key authentication
def process_marketplace_transaction(request):
    """
    Webhook for Node.js to trigger reward distribution when marketplace transaction completes.

    Expected payload:
    {
        "listing_id": "uuid",
        "disposer_id": "uuid",
        "recycler_id": "uuid",
        "quantity": 25.5,
        "waste_type": "Plastic",
        "price": 255.00
    }
    """
    try:
        listing_id = request.data.get('listing_id')
        disposer_id = request.data.get('disposer_id')
        recycler_id = request.data.get('recycler_id')
        quantity = request.data.get('quantity')
        waste_type = request.data.get('waste_type', 'plastic')
        price = Decimal(str(request.data.get('price', 0)))

        # Validate required fields
        if not all([listing_id, disposer_id, recycler_id, quantity]):
            return Response({
                'success': False,
                'message': 'Missing required fields'
            }, status=400)

        # Get or create users
        disposer = User.objects.get(id=disposer_id)
        recycler = User.objects.get(id=recycler_id)

        # Get or create listing
        listing, _ = Listing.objects.get_or_create(
            id=listing_id,
            defaults={
                'user_id': disposer,
                'waste_type': waste_type,
                'quantity': quantity,
                'status': 'completed',
                'reward_estimate': price,
                'final_reward': price,
                'pickup_location': {}
            }
        )

        # Update listing to completed
        listing.status = 'completed'
        listing.final_reward = price
        listing.save()

        # Get or create marketplace listing
        mp_listing, _ = MarketplaceListing.objects.get_or_create(
            listing_id=listing,
            defaults={
                'recycler_id': recycler,
                'price': price,
                'escrow_status': 'released'
            }
        )

        # Update to released if not already
        if mp_listing.escrow_status != 'released':
            mp_listing.recycler_id = recycler
            mp_listing.escrow_status = 'released'
            mp_listing.save()

        # Process rewards
        results = process_marketplace_rewards(mp_listing)

        return Response({
            'success': True,
            'message': 'Rewards processed successfully',
            'results': {
                'disposer_reward': str(results['disposer_reward']) if results['disposer_reward'] else None,
                'recycler_reward': str(results['recycler_reward']) if results['recycler_reward'] else None,
                'disposer_referrer_bonus': str(results['disposer_referrer_reward']) if results['disposer_referrer_reward'] else None,
                'recycler_referrer_bonus': str(results['recycler_referrer_reward']) if results['recycler_referrer_reward'] else None,
                'errors': results['errors']
            }
        }, status=200)

    except User.DoesNotExist:
        return Response({
            'success': False,
            'message': 'User not found'
        }, status=404)
    except Exception as e:
        logger.error(f"Error processing marketplace transaction: {str(e)}")
        return Response({
            'success': False,
            'message': str(e)
        }, status=500)
```

**File:** `apps/wallet/urls.py`

Add the route:

```python
path('marketplace-transaction/', views.process_marketplace_transaction, name='marketplace-transaction'),
```

---

### 2. **Update Node.js Service**

**Location:** Your Node.js backend (wasteworth-backend-express)

When a marketplace transaction is completed (escrow released), Node.js should call Django:

```javascript
// In your marketplace/escrow controller
async function releaseEscrow(listingId, recyclerId) {
  try {
    // 1. Update Node.js database - mark transaction as completed
    const listing = await Listing.findByPk(listingId);
    const marketplaceListing = await MarketplaceListing.update(
      { status: 'completed', escrow_status: 'released' },
      { where: { listing_id: listingId } }
    );

    // 2. Call Django webhook to process rewards
    const djangoResponse = await axios.post(
      'https://wasteworth-backend-django.onrender.com/api/v1/wallet/marketplace-transaction/',
      {
        listing_id: listing.id,
        disposer_id: listing.user_id_id,
        recycler_id: recyclerId,
        quantity: listing.quantity,
        waste_type: listing.waste_type,
        price: listing.reward_estimate
      },
      {
        headers: {
          'Authorization': `Bearer ${internalApiKey}`, // Use internal API key
          'Content-Type': 'application/json'
        }
      }
    );

    console.log('Rewards processed:', djangoResponse.data);

    return { success: true, rewards: djangoResponse.data };

  } catch (error) {
    console.error('Error releasing escrow:', error);
    throw error;
  }
}
```

---

### 3. **Security Considerations**

The webhook endpoint should be secured. You have two options:

**Option A: Internal API Key** (Recommended)

Add to Django `.env`:
```
INTERNAL_API_KEY=your-secret-key-here
```

Add middleware or decorator to validate:
```python
def internal_api_required(view_func):
    def wrapper(request, *args, **kwargs):
        api_key = request.headers.get('X-Internal-API-Key')
        if api_key != settings.INTERNAL_API_KEY:
            return Response({'error': 'Unauthorized'}, status=401)
        return view_func(request, *args, **kwargs)
    return wrapper

@api_view(['POST'])
@internal_api_required
def process_marketplace_transaction(request):
    # ... view code
```

**Option B: Service Account** (Alternative)

Create a system user in Django and use JWT authentication.

---

### 4. **Node.js Marketplace Flow**

The complete Node.js flow should be:

```
1. Disposer creates listing (already working ✅)
   POST /api/v1/listings

2. Recycler views marketplace (already working ✅)
   GET /api/v1/listings

3. Recycler accepts/purchases listing
   POST /api/v1/marketplace/accept/:listingId
   - Lock escrow
   - Update status to 'in-progress'

4. Recycler collects waste & disposer confirms
   POST /api/v1/marketplace/confirm/:listingId
   - Verify collection
   - Release escrow
   - **Call Django webhook** (NEW)

5. Django processes rewards (NEW ✅ logic exists)
   - Distribute activity rewards
   - Handle referral bonuses
   - Record transactions

6. Both users see updated points in wallet (already working ✅)
   GET /api/v1/wallet/balance/
```

---

## Summary of Required Changes

### Django (Backend 1):
1. ✅ Reward distribution logic - Already exists
2. ❌ Webhook endpoint - **Needs to be created**
3. ❌ URL route - **Needs to be added**
4. ❌ Internal API key authentication - **Needs to be added**

### Node.js (Backend 2):
1. ✅ Listing creation - Already working
2. ❌ Marketplace acceptance endpoint - **Check if exists**
3. ❌ Escrow release endpoint - **Check if exists**
4. ❌ Django webhook call - **Needs to be added**

### Testing Checklist:
- [ ] Create webhook endpoint in Django
- [ ] Test webhook with curl/Postman
- [ ] Update Node.js to call webhook
- [ ] Test full E2E flow:
  - [ ] Disposer creates listing
  - [ ] Recycler accepts listing
  - [ ] Transaction completes
  - [ ] Escrow released
  - [ ] Django webhook called
  - [ ] Rewards distributed
  - [ ] Wallet balances updated

---

## Quick Test Command

After implementing the webhook, test it with:

```bash
curl -X POST "https://wasteworth-backend-django.onrender.com/api/v1/wallet/marketplace-transaction/" \
  -H "Authorization: Bearer YOUR_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "listing_id": "502a6553-73fe-4a3c-a67f-0205141d4e95",
    "disposer_id": "5d806d6e-af10-4fc2-b453-0b8edc37687e",
    "recycler_id": "846ccd72-1316-431e-a7e3-6f6379d812a6",
    "quantity": 25.5,
    "waste_type": "Plastic",
    "price": 255.00
  }'
```

Expected response:
```json
{
  "success": true,
  "message": "Rewards processed successfully",
  "results": {
    "disposer_reward": "Activity_Reward - 255 for Test Disposer",
    "recycler_reward": "Activity_Reward - 255 for Test Recycler",
    "disposer_referrer_bonus": null,
    "recycler_referrer_bonus": "Referral_Reward - 100 for Test Recycler",
    "errors": []
  }
}
```
