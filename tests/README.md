# Test Files

This folder contains all test scripts for the Wasteworth backend.

## Rate Limiting Tests

### Main Test Script
- **`test_all_rate_limiting.py`** - Comprehensive test for all rate-limited endpoints (7 endpoints)
  ```bash
  python tests/test_all_rate_limiting.py
  ```

### Specialized Tests
- **`test_axes_only.py`** - Tests django-axes account lockout in isolation
- **`test_class_based_rate_limits.py`** - Tests rate limiting on class-based views
- **`test_django_axes.py`** - Django-axes integration test
- **`test_rate_limiting.py`** - Basic rate limiting test

### Utility Scripts
- **`clear_redis.py`** - Clears rate limiting keys from Redis
  ```bash
  python tests/clear_redis.py
  ```

- **`test_redis_connection.py`** - Tests connection to Redis Cloud
  ```bash
  python tests/test_redis_connection.py
  ```

## Configuration Check Scripts
- **`check_axes_config.py`** - Validates django-axes configuration
- **`check_db_schema.py`** - Database schema validation
- **`check_production_schema.py`** - Production database checks

## API Tests
- **`test_activity_reward_api.py`** - Activity reward endpoint tests
- **`test_complete_listing.py`** - Listing completion tests

## Running Tests

### Before Running Tests
1. Ensure Django server is running: `python manage.py runserver`
2. Ensure Redis is connected (local or cloud)
3. Clear Redis cache if needed: `python tests/clear_redis.py`

### Run All Rate Limiting Tests
```bash
python tests/test_all_rate_limiting.py
```

### Test Individual Components
```bash
# Test Redis connection
python tests/test_redis_connection.py

# Test axes configuration
python tests/check_axes_config.py

# Clear rate limits
python tests/clear_redis.py
```

## Expected Test Results

When running `test_all_rate_limiting.py`, you should see:
```
Total Tests: 7
Passed: 7
Failed: 0

All endpoints correctly return 429 after limits exceeded!
```
