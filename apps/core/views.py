"""
Core application views - Health checks and utility endpoints
"""
from django.http import JsonResponse
from django.views.decorators.http import require_http_methods
from django.views.decorators.cache import cache_page
from django.db import connections
from django.conf import settings
import redis
import logging

logger = logging.getLogger(__name__)


@require_http_methods(["GET", "HEAD"])
@cache_page(60)  # Cache for 60 seconds
def health_check(request):
    """
    Health check endpoint for monitoring services (Render, AWS, etc.)

    GET/HEAD /
    GET/HEAD /health/

    Returns 200 if service is healthy, 503 if not.
    """
    health_status = {
        'status': 'healthy',
        'service': 'wasteworth-backend-django',
        'version': '1.0.0',
        'checks': {}
    }

    is_healthy = True

    # Check database connection
    try:
        connections['default'].ensure_connection()
        health_status['checks']['database'] = 'connected'
    except Exception as e:
        health_status['checks']['database'] = f'error: {str(e)}'
        is_healthy = False
        logger.error(f"Database health check failed: {str(e)}")

    # Check Redis connection (optional - don't fail if Redis is down)
    try:
        if hasattr(settings, 'REDIS_HOST'):
            r = redis.Redis(
                host=settings.REDIS_HOST,
                port=settings.REDIS_PORT,
                password=settings.REDIS_PASSWORD,
                socket_connect_timeout=2
            )
            r.ping()
            health_status['checks']['redis'] = 'connected'
    except Exception as e:
        # Redis failure is non-critical - log but don't fail health check
        health_status['checks']['redis'] = f'unavailable: {str(e)}'
        logger.warning(f"Redis health check failed (non-critical): {str(e)}")

    # Set overall status
    if not is_healthy:
        health_status['status'] = 'unhealthy'

    # For HEAD requests, just return status code
    if request.method == 'HEAD':
        return JsonResponse({}, status=200 if is_healthy else 503)

    # For GET requests, return full status
    return JsonResponse(
        health_status,
        status=200 if is_healthy else 503
    )


@require_http_methods(["GET"])
def api_root(request):
    """
    API root endpoint - provides API information

    GET /api/v1/
    """
    return JsonResponse({
        'service': 'Wasteworth Backend API',
        'version': '1.0.0',
        'documentation': 'https://github.com/InternPulse/wasteworth-backend-django/blob/development/API_DOCUMENTATION.md',
        'endpoints': {
            'health': '/',
            'auth': {
                'signup': '/api/v1/users/signup/',
                'login': '/api/v1/users/login/',
                'logout': '/api/v1/users/logout/',
                'token_refresh': '/api/v1/auth/token/refresh/'
            },
            'users': {
                'disposer_dashboard': '/api/v1/users/disposer-dashboard/',
                'recycler_dashboard': '/api/v1/users/recycler-dashboard/',
                'update_profile': '/api/v1/users/update-user/'
            },
            'wallet': {
                'balance': '/api/v1/wallet/balance/',
                'transactions': '/api/v1/wallet/transactions/',
                'redeem': '/api/v1/wallet/redeem/'
            },
            'payments': {
                'initialize': '/api/v1/payments/initialize/',
                'verify': '/api/v1/payments/verify/',
                'confirm_release': '/api/v1/payments/confirm-release/',
                'confirm_receipt': '/api/v1/payments/confirm-receipt/'
            },
            'otp': {
                'send': '/api/v1/otp/send/',
                'verify': '/api/v1/otp/verify/',
                'resend': '/api/v1/otp/resend/'
            },
            'contact': '/api/v1/contact/'
        }
    })
