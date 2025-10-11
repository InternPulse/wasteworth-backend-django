# Rate Limiting Implementation - Complete Guide

## ✅ Implementation Status

All rate limiting has been successfully implemented:

- ✅ Django-axes installed and configured
- ✅ Redis token bucket rate limiter created
- ✅ Rate limiting applied to 11 endpoints
- ✅ Migrations completed

## 📊 Rate Limits Summary

### OTP Endpoints
| Endpoint | Rate Limit | Type |
|----------|------------|------|
| `/api/v1/otp/send/` | 3 requests/hour | Per IP |
| `/api/v1/otp/verify/` | 10 requests/10min | Per IP |
| `/api/v1/otp/resend/` | 5 requests/hour | Per IP |

### Authentication Endpoints
| Endpoint | Rate Limit | Type |
|----------|------------|------|
| `/api/v1/users/signup/` | 10 requests/day | Per IP |
| `/api/v1/users/login/` | 10 requests/10min + axes lockout after 5 failures | Per IP |
| `/api/v1/users/logout/` | 20 requests/minute | Per User |
| `/api/v1/users/forgotPassword/` | 3 requests/hour | Per IP |
| `/api/v1/users/resetPassword/` | 5 requests/hour | Per IP |
| `/api/v1/users/updatePassword/` | 5 requests/hour | Per User |

### Wallet Endpoints
| Endpoint | Rate Limit | Type |
|----------|------------|------|
| `/api/v1/wallet/transactions/` | 100 requests/minute | Per User |
| `/api/v1/wallet/redeem/` | 20 requests/hour | Per User |

## 🚀 Testing Instructions

### Option 1: Automated Test Script

Run the comprehensive test script:

```bash
# Make sure Django server is running in another terminal
python manage.py runserver

# In a new terminal, run the test script
python test_rate_limiting.py
```

### Option 2: Manual Testing with cURL

#### Test 1: OTP Rate Limiting (3 requests/hour)

```bash
# Run this command 4 times - should block on the 4th attempt
curl -X POST http://127.0.0.1:8000/api/v1/otp/send/ \
  -H "Content-Type: application/json" \
  -d "{\"email_or_phone\": \"test@example.com\", \"purpose\": \"signup\"}"
```

Expected result on 4th attempt:
```json
{
  "success": false,
  "error": {
    "code": "RATE_LIMIT_EXCEEDED",
    "message": "Too many requests. Please try again in 3600 seconds.",
    "details": {
      "rate_limit": ["Limit: 3 requests per 3600 seconds"],
      "retry_after": ["3600 seconds"]
    }
  }
}
```

#### Test 2: Login Rate Limiting (django-axes)

```bash
# Try 6 failed login attempts - should lock out on the 6th
for i in {1..6}; do
  echo "Attempt $i:"
  curl -X POST http://127.0.0.1:8000/api/v1/users/login/ \
    -H "Content-Type: application/json" \
    -d "{\"email\": \"test@example.com\", \"password\": \"wrongpassword\"}"
  echo -e "\n"
done
```

Expected result after 5 failures:
```json
{
  "success": false,
  "error": {
    "code": "AXES_LOCKED",
    "message": "Too many failed login attempts. Your account has been temporarily locked for security. Please try again in 30 minutes."
  }
}
```

#### Test 3: Signup Rate Limiting (10/day)

```bash
# Run this 11 times - should block on the 11th
for i in {1..11}; do
  echo "Signup attempt $i:"
  curl -X POST http://127.0.0.1:8000/api/v1/users/signup/ \
    -H "Content-Type: application/json" \
    -d "{
      \"name\": \"Test User $i\",
      \"email\": \"testuser$i@example.com\",
      \"phone\": \"08012345678$i\",
      \"password\": \"TestPass123!\",
      \"confirm_password\": \"TestPass123!\",
      \"role\": \"disposer\"
    }"
  echo -e "\n"
done
```

## 🔍 Monitoring Rate Limits

### Check Redis Keys

```bash
# Connect to Redis
redis-cli

# List all rate limit keys
KEYS ratelimit:*

# Check specific key
GET ratelimit:otp_send:127.0.0.1

# Check TTL (time to live)
TTL ratelimit:otp_send:127.0.0.1

# Exit Redis
exit
```

### Check Django-Axes Admin

1. Go to: `http://127.0.0.1:8000/admin/`
2. Login with your superuser account
3. Navigate to: **AXES** > **Access attempts**
4. View all failed login attempts and lockouts

To create a superuser if you don't have one:
```bash
python manage.py createsuperuser
```

### Reset Rate Limits

**Reset Redis rate limits:**
```bash
redis-cli
FLUSHDB  # Clear all rate limit counters
exit
```

**Reset django-axes lockouts:**
```bash
python manage.py axes_reset
# Or reset specific user
python manage.py axes_reset_username test@example.com
# Or reset specific IP
python manage.py axes_reset_ip 127.0.0.1
```

## 🐛 Troubleshooting

### Issue 1: Rate limiting not working

**Symptoms:** Requests are not being blocked even after exceeding limits

**Solution:**
```bash
# Check if Redis is running
redis-cli ping
# Should return: PONG

# If not running, start Redis
redis-server

# Check Django logs for rate limiter warnings
# You should see: "Redis connection successful for rate limiting"
```

### Issue 2: Redis connection failed

**Symptoms:** Log shows "Redis not available for rate limiting"

**Solution:**
The system will fail open (allow all requests). To fix:

1. Install Redis:
   ```bash
   # Windows (with Chocolatey)
   choco install redis

   # Mac
   brew install redis

   # Ubuntu
   sudo apt-get install redis
   ```

2. Start Redis:
   ```bash
   redis-server
   ```

3. Restart Django server

### Issue 3: Django-axes not blocking logins

**Symptoms:** Can attempt unlimited failed logins

**Solution:**
```bash
# Verify axes is in INSTALLED_APPS
python manage.py shell
>>> from django.conf import settings
>>> 'axes' in settings.INSTALLED_APPS
True

# Check axes tables exist
python manage.py migrate axes

# Check axes middleware is active
>>> 'axes.middleware.AxesMiddleware' in settings.MIDDLEWARE
True
```

## 📝 Configuration Files Changed

### 1. `config/settings.py`
- Added 'axes' to INSTALLED_APPS
- Added AxesMiddleware
- Added AUTHENTICATION_BACKENDS
- Added django-axes configuration
- Added Redis cache configuration

### 2. `utils/rate_limiter.py` (NEW)
- Custom Redis token bucket implementation
- Helper functions: `ip_key()`, `user_key()`, `user_ip_key()`

### 3. `apps/otp/views.py`
- Added rate limiting to: `send_otp`, `verify_otp`, `resend_otp`

### 4. `apps/users/views.py`
- Added rate limiting to: `signup`, `login`, `logout`, `ForgotPasswordView`, `UpdatePasswordView`, `ResetPasswordView`

### 5. `apps/wallet/views.py`
- Added rate limiting to: `WalletTransactionsView`, `RedeemPointsView`

### 6. `requirements.txt`
- Added: django-axes==6.1.1
- Added: django-redis==5.4.0
- Added: redis==5.0.1

## 🔐 Security Features

### Django-axes Protection
- Tracks failed login attempts by IP + username
- Locks accounts for 30 minutes after 5 failed attempts
- Resets counter on successful login
- Admin interface for monitoring/resetting

### Redis Rate Limiting
- Token bucket algorithm
- Distributed-ready (works across multiple servers)
- Fail-open design (allows requests if Redis is down)
- Granular control per endpoint
- Automatic TTL expiration

## 📈 Production Deployment

### Environment Variables Required

Add to your `.env` file:

```env
# Redis Configuration (Production)
REDIS_HOST=your-redis-host.com
REDIS_PORT=6379
REDIS_PASSWORD=your-secure-redis-password

# Database (Production)
USE_POSTGRES=True
DATABASE_NAME=wasteworth_prod
DATABASE_USER=prod_user
DATABASE_PASSWORD=secure_password
DATABASE_HOST=your-db-host.com
```

### Redis Deployment Options

1. **AWS ElastiCache** (Recommended)
   - Managed Redis service
   - Automatic failover
   - Backups included

2. **Railway/Render Redis**
   - Easy setup
   - Good for small projects

3. **Self-hosted Redis**
   - Full control
   - Requires maintenance

### Monitoring in Production

```bash
# Check rate limiting logs
tail -f logs/django.log | grep "rate limit"

# Monitor Redis memory
redis-cli info memory

# Check axes lockouts
python manage.py axes_list_attempts
```

## ✅ Success Checklist

- [ ] Redis installed and running
- [ ] Django migrations completed
- [ ] Requirements.txt updated
- [ ] Django server starts without errors
- [ ] OTP rate limiting works (3/hour)
- [ ] Login lockout works (5 attempts)
- [ ] Signup rate limiting works (10/day)
- [ ] Wallet redemption limiting works (20/hour)
- [ ] Axes admin panel accessible
- [ ] Redis keys visible in redis-cli

## 🎯 Next Steps

1. Test all endpoints with automated script
2. Verify rate limiting in production environment
3. Set up monitoring/alerting for high rate limit violations
4. Document rate limits in API documentation
5. Add rate limit headers to responses (optional enhancement)

## 📚 Additional Resources

- [Django-axes Documentation](https://django-axes.readthedocs.io/)
- [Redis Documentation](https://redis.io/documentation)
- [Django-redis Cache](https://github.com/jazzband/django-redis)
