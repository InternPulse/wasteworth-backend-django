# Rate Limiting Test Guide

## Quick Test Instructions

### 1. Restart Django Server
```bash
python manage.py runserver
```

### 2. Run Rate Limiting Tests
```bash
python test_rate_limiting.py
```

### 3. Expected Results

**OTP Send Endpoint** (`/api/v1/otp/send-otp/`)
- Limit: 3 requests per hour (3600 seconds)
- First 3 requests: `200 OK`
- 4th request onwards: `429 Too Many Requests`

**OTP Verify Endpoint** (`/api/v1/otp/verify-otp/`)
- Limit: 10 requests per 10 minutes (600 seconds)
- First 10 requests: May return validation errors (expected)
- 11th request onwards: `429 Too Many Requests`

**Login Endpoint** (`/api/v1/users/login/`)
- Rate limiting: 10 requests per 10 minutes (600 seconds)
- Django-axes: 5 failed attempts = 30 minute lockout
- First 10 requests: May return validation errors
- 11th request onwards: `429 Too Many Requests`

### 4. Expected 429 Response Format

```json
{
  "success": false,
  "message": "Too many requests. Please slow down and try again later.",
  "error": {
    "code": "RATE_LIMIT_EXCEEDED",
    "message": "Too many requests. Please slow down and try again later.",
    "details": {
      "retry_after": ["3599 seconds"]
    }
  }
}
```

Response should also include `Retry-After` header with seconds to wait.

## Manual Testing with cURL

### Test OTP Send Rate Limit
```bash
# Request 1-3 should succeed (or return validation errors)
curl -X POST http://127.0.0.1:8000/api/v1/otp/send-otp/ \
  -H "Content-Type: application/json" \
  -d '{"email": "test@example.com", "purpose": "registration"}'

# Request 4 should return 429
curl -X POST http://127.0.0.1:8000/api/v1/otp/send-otp/ \
  -H "Content-Type: application/json" \
  -d '{"email": "test@example.com", "purpose": "registration"}'
```

### Test Login Rate Limit
```bash
# Requests 1-10 should return validation errors (400)
for i in {1..11}; do
  echo "Request $i:"
  curl -X POST http://127.0.0.1:8000/api/v1/users/login/ \
    -H "Content-Type: application/json" \
    -d '{"email": "test@example.com", "password": "wrongpassword"}' \
    -w "\nHTTP Status: %{http_code}\n\n"
done
```

## Clear Redis Cache (for fresh testing)

If you need to reset rate limits for testing:

```bash
# Connect to Redis CLI
redis-cli

# Inside Redis CLI:
FLUSHDB
```

Or use Python:
```python
import redis
r = redis.Redis(host='localhost', port=6379, db=0)
r.flushdb()
```

## Troubleshooting

### Issue: All requests return 500 errors
**Solution**: Check that Throttled exception is being handled before DRF's default exception handler in `utils/error_handler.py`

### Issue: Rate limiting not working (no 429 errors)
**Solution**:
- Check Redis is running: `redis-cli ping` (should return "PONG")
- Check rate_limiter.py is properly catching and re-raising Throttled exceptions
- Check decorator is applied to view functions

### Issue: Django-axes not locking out after 5 failed login attempts
**Status**: Under investigation
**Workaround**: Rate limiting (10 requests per 10 minutes) provides protection

## Rate Limits Summary

| Endpoint | Limit | Period | Key Type |
|----------|-------|--------|----------|
| OTP Send | 3 | 1 hour | IP |
| OTP Verify | 10 | 10 minutes | IP |
| OTP Resend | 5 | 1 hour | IP |
| Signup | 10 | 1 day | IP |
| Login | 10 | 10 minutes | IP |
| Logout | 20 | 1 minute | User/IP |
| Forgot Password | 3 | 1 hour | IP |
| Reset Password | 5 | 1 hour | IP |
| Update Password | 5 | 1 hour | User |
| Wallet Transactions | 100 | 1 minute | User |
| Redeem Points | 20 | 1 hour | User |

## Files Modified

1. `config/settings.py` - Django-axes + Redis cache configuration
2. `utils/rate_limiter.py` - Custom Redis token bucket implementation
3. `utils/error_handler.py` - Throttled exception handling
4. `apps/otp/views.py` - Rate limiting decorators
5. `apps/users/views.py` - Rate limiting decorators
6. `apps/wallet/views.py` - Rate limiting decorators
7. `requirements.txt` - New dependencies

## Next Steps

After confirming rate limiting works:
1. Investigate why django-axes is not locking out after 5 failed login attempts
2. Consider adjusting rate limits based on production usage patterns
3. Set up monitoring for rate limit violations
4. Document rate limits in API documentation for frontend team
