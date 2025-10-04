"""
Logging filters to prevent sensitive data exposure in logs.
Middleware for logging API requests and responses.
"""
import logging
import re
import time
from django.utils.deprecation import MiddlewareMixin


class SensitiveDataFilter(logging.Filter):
    """
    Filter to redact sensitive data from log messages.
    Automatically masks API keys, tokens, passwords, and secrets.
    """

    SENSITIVE_PATTERNS = [
        # API Keys and tokens (hex strings)
        (r'(api_key["\']?\s*[:=]\s*["\']?Bearer\s+)([a-zA-Z0-9\-_\.]{32,})', r'\1<REDACTED>'),
        (r'(api_key["\']?\s*[:=]\s*["\']?)([a-zA-Z0-9\-_\.]{32,})', r'\1<REDACTED>'),

        # Bearer tokens (JWTs and other tokens)
        (r'(Bearer\s+)([a-zA-Z0-9\-_\.]{20,})', r'\1<REDACTED>'),

        # Authorization headers
        (r'(Authorization["\']?\s*[:=]\s*["\']?[^"\']+)([a-zA-Z0-9\-_\.]{20,})', r'\1<REDACTED>'),

        # Passwords
        (r'(password["\']?\s*[:=]\s*["\']?)([^"\']{4,})', r'\1<REDACTED>'),

        # Secret keys
        (r'(secret[_\s]?key["\']?\s*[:=]\s*["\']?)([^"\']+)', r'\1<REDACTED>'),

        # Internal API key environment variable value
        (r'(INTERNAL_API_KEY["\']?\s*[:=]\s*["\']?)([a-zA-Z0-9\-_\.]{32,})', r'\1<REDACTED>'),
    ]

    def filter(self, record):
        """Redact sensitive data from log record"""
        # Redact from message
        if hasattr(record, 'msg'):
            message = str(record.msg)
            for pattern, replacement in self.SENSITIVE_PATTERNS:
                message = re.sub(pattern, replacement, message, flags=re.IGNORECASE)
            record.msg = message

        # Redact from args (used in formatting)
        if hasattr(record, 'args') and record.args:
            if isinstance(record.args, dict):
                record.args = self._redact_dict(record.args)
            elif isinstance(record.args, (list, tuple)):
                record.args = tuple(self._redact_value(arg) for arg in record.args)

        return True

    def _redact_dict(self, data):
        """Recursively redact sensitive keys from dictionary"""
        if not isinstance(data, dict):
            return data

        redacted = {}
        sensitive_keys = {'api_key', 'authorization', 'bearer', 'password', 'secret', 'token'}

        for key, value in data.items():
            key_lower = str(key).lower()

            # Check if key contains sensitive keyword
            if any(sensitive in key_lower for sensitive in sensitive_keys):
                redacted[key] = '<REDACTED>'
            elif isinstance(value, dict):
                redacted[key] = self._redact_dict(value)
            elif isinstance(value, str):
                redacted[key] = self._redact_value(value)
            else:
                redacted[key] = value

        return redacted

    def _redact_value(self, value):
        """Redact sensitive patterns from string values"""
        if not isinstance(value, str):
            return value

        for pattern, replacement in self.SENSITIVE_PATTERNS:
            value = re.sub(pattern, replacement, value, flags=re.IGNORECASE)

        return value


class RequestResponseLoggingMiddleware(MiddlewareMixin):
    """
    Middleware to log all API requests and responses.
    Filters sensitive data automatically using SensitiveDataFilter.
    """

    # Paths to exclude from logging (health checks, static files, etc.)
    EXCLUDED_PATHS = [
        '/health/',
        '/static/',
        '/media/',
        '/admin/jsi18n/',
    ]

    def process_request(self, request):
        """Record start time for response time calculation."""
        request.start_time = time.time()

    def process_response(self, request, response):
        """Log request and response details."""
        # Skip excluded paths
        if any(request.path.startswith(path) for path in self.EXCLUDED_PATHS):
            return response

        # Calculate request duration
        duration = time.time() - getattr(request, 'start_time', time.time())
        duration_ms = round(duration * 1000)  # Convert to milliseconds

        # Get user info (if authenticated)
        user_info = "Anonymous"
        if hasattr(request, 'user') and request.user.is_authenticated:
            user_info = f"{request.user.email} (ID: {request.user.id})"

        # Get IP address
        ip = self._get_client_ip(request)

        # Build log data
        log_data = {
            'method': request.method,
            'path': request.path,
            'user': user_info,
            'ip': ip,
            'status': response.status_code,
            'duration_ms': duration_ms
        }

        # Format log message
        log_message = (
            f"{request.method} {request.path} - "
            f"user: {user_info} - "
            f"ip: {ip} - "
            f"{response.status_code} - "
            f"{duration_ms}ms"
        )

        # Get logger (uses SensitiveDataFilter from settings)
        logger = logging.getLogger('api')

        # Log based on status code
        if response.status_code >= 500:
            logger.error(log_message, extra=log_data)
        elif response.status_code >= 400:
            logger.warning(log_message, extra=log_data)
        else:
            logger.info(log_message, extra=log_data)

        return response

    def _get_client_ip(self, request):
        """Get client IP address from request headers."""
        x_forwarded_for = request.META.get('HTTP_X_FORWARDED_FOR')
        if x_forwarded_for:
            # X-Forwarded-For can contain multiple IPs, get the first one
            ip = x_forwarded_for.split(',')[0].strip()
        else:
            ip = request.META.get('REMOTE_ADDR', 'unknown')
        return ip
