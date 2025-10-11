import redis

# Connect to Redis
r = redis.Redis(host='localhost', port=6379, db=0, decode_responses=True)

# Clear all rate limiting keys
keys = r.keys('ratelimit:*')
if keys:
    deleted = r.delete(*keys)
    print(f"Cleared {deleted} rate limiting keys from Redis")
else:
    print("No rate limiting keys found in Redis")

# Show remaining keys
remaining = r.dbsize()
print(f"Total keys remaining in Redis DB 0: {remaining}")
