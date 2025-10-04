from django.core.cache import cache
from django.http import JsonResponse
from functools import wraps
import logging

logger = logging.getLogger(__name__)


def rate_limit(key_func,rate,per,block=True):
    """
    Token bucket rate limiter using Redis
    
    Args:
        key_func: Function that takes request and returns rate limit key
        rate: Number of requests allowed
        per: Time period in seconds
        block: If True, return 429 when exceeded. If False, just log and continue.
    
    Usage:
        @rate_limit(
            key_func=lambda req: f"ratelimit:login:{req.META.get('REMOTE_ADDR')}",
            rate=5,
            per=60
        )
    """
    def decorator(view_func):
        @wraps(view_func)
        def wrapper(*args, **kwargs):
            # Handle both function-based views and class-based view methods
            if args and hasattr(args[0], 'META'):
                # First arg is request (function-based view)
                request = args[0]
            elif len(args) > 1 and hasattr(args[1], 'META'):
                # Second arg is request (class-based view method)
                request = args[1]
            else:
                # Fallback - can't find request, skip rate limiting
                logger.warning("Rate limiting skipped - could not find request object")
                return view_func(*args, **kwargs)


            try:
                limit_key = key_func(request)
                current = cache.get(limit_key)

                if current is None:
                    # First request - set counter and TTL
                    cache.set(limit_key, 1, per)
                    logger.debug(f"Rate limit initialized for key: {limit_key}")

                elif int(current) >= rate:
                    # Rate limit exceeded
                    # Use configured period as TTL estimate
                    ttl = per
                    logger.warning(f"Rate limit exceeded for key: {limit_key}, retry after: {ttl}s")

                    if block:
                        # Return 429 response directly using JsonResponse
                        error_response = {
                            'success': False,
                            'message': 'Too many requests. Please slow down and try again later.',
                            'error': {
                                'code': 'RATE_LIMIT_EXCEEDED',
                                'message': 'Too many requests. Please slow down and try again later.',
                                'details': {
                                    'retry_after': [f'{ttl} seconds']
                                }
                            }
                        }
                        response = JsonResponse(error_response, status=429)
                        response['Retry-After'] = str(int(ttl))
                        return response
                else:
                    # Increment counter
                    try:
                        cache.incr(limit_key)
                        logger.debug(f"Rate limit counter incremented for key: {limit_key}")
                    except ValueError:
                        # Key doesn't exist or expired, reset it
                        cache.set(limit_key, 1, per)
                        logger.debug(f"Rate limit key expired, reinitialized: {limit_key}")

            except Exception as e:
                # Log other errors but allow request (fail open)
                logger.error(f"Rate limiting error: {str(e)}")

            return view_func(*args, **kwargs)
        return wrapper
    return decorator

def get_client_ip(request):

    x_forwarded_for = request.META.get('HTTP_X_FORWARDED_FOR')

    if x_forwarded_for:
        ip = x_forwarded_for.split(',')[0].strip()

    else:
        ip = request.META.get('REMOTE_ADDR')
    return ip

def ip_key(prefix):
    """Rate limit by IP address"""
    return lambda req: f"ratelimit:{prefix}:{get_client_ip(req)}"

def user_key(prefix):
    """Rate limit by authenticated user"""
    return lambda req: f"ratelimit:{prefix}:user:{req.user.id if req.user.is_authenticated else get_client_ip(req)}"

def user_ip_key(prefix):
    """Rate limit by user + IP combination (stricter)"""
    return lambda req: f"ratelimit:{prefix}:user:{req.user.id if req.user.is_authenticated else 'anon'}:ip:{get_client_ip(req)}"
