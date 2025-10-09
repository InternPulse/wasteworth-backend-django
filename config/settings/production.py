"""
Production settings for WasteWorth project.

Security-hardened configuration for production deployment.
All sensitive values MUST come from environment variables with no defaults.
"""

from .base import *
from decouple import config

# ===================================================================
# CORE DJANGO SETTINGS
# ===================================================================

# Debug is ALWAYS False in production (not configurable)
DEBUG = False

# Secret key MUST be set - no default allowed
SECRET_KEY = config('SECRET_KEY')

# Allowed hosts MUST be explicitly configured
ALLOWED_HOSTS = config('ALLOWED_HOSTS').split(',')

# Validate that we're not using insecure defaults
if SECRET_KEY == 'django-insecure-fallback-key' or 'insecure' in SECRET_KEY.lower():
    raise ValueError(
        "Production SECRET_KEY must be set to a secure random value. "
        "Generate one using: python -c 'from django.core.management.utils import get_random_secret_key; print(get_random_secret_key())'"
    )


# ===================================================================
# DATABASE CONFIGURATION
# ===================================================================

# Production ALWAYS uses PostgreSQL
DATABASES = {
    'default': {
        'ENGINE': 'django.db.backends.postgresql',
        'NAME': config('DATABASE_NAME'),
        'USER': config('DATABASE_USER'),
        'PASSWORD': config('DATABASE_PASSWORD'),
        'HOST': config('DATABASE_HOST'),
        'PORT': config('DATABASE_PORT', default='5432'),
        'OPTIONS': {
            'sslmode': config('SSL_MODE', default='require'),
        },
        # Connection pooling to prevent intermittent connection failures
        'CONN_MAX_AGE': 600,  # Keep connections alive for 10 minutes
        'CONN_HEALTH_CHECKS': True,  # Check connection health before using
    }
}


# ===================================================================
# SECURITY SETTINGS (Always Enabled in Production)
# ===================================================================

# Force HTTPS redirect
SECURE_SSL_REDIRECT = True

# HTTP Strict Transport Security (HSTS)
SECURE_HSTS_SECONDS = 31536000  # 1 year
SECURE_HSTS_INCLUDE_SUBDOMAINS = True
SECURE_HSTS_PRELOAD = True

# Secure cookies (HTTPS only)
SESSION_COOKIE_SECURE = True
CSRF_COOKIE_SECURE = True

# Proxy configuration (for reverse proxies like Nginx)
SECURE_PROXY_SSL_HEADER = ('HTTP_X_FORWARDED_PROTO', 'https')


# ===================================================================
# CORS CONFIGURATION
# ===================================================================

# Production origins must be explicitly configured
CORS_ALLOWED_ORIGINS = config('CORS_ALLOWED_ORIGINS').split(',')

# Validate CORS origins
for origin in CORS_ALLOWED_ORIGINS:
    if not origin.startswith('https://') and not origin.startswith('http://localhost'):
        raise ValueError(
            f"Invalid CORS origin in production: {origin}. "
            "Production origins must use HTTPS (except localhost for testing)."
        )


# ===================================================================
# EMAIL CONFIGURATION
# ===================================================================

EMAIL_BACKEND = config(
    'EMAIL_BACKEND',
    default='utils.email_backend.SMTPBackendWithTimeout'
)
EMAIL_HOST = config('EMAIL_HOST')
EMAIL_PORT = config('EMAIL_PORT', cast=int)
EMAIL_USE_TLS = config('EMAIL_USE_TLS', default=False, cast=bool)
EMAIL_USE_SSL = config('EMAIL_USE_SSL', default=True, cast=bool)
EMAIL_HOST_USER = config('EMAIL_HOST_USER')
EMAIL_HOST_PASSWORD = config('EMAIL_HOST_PASSWORD')
DEFAULT_FROM_EMAIL = config('DEFAULT_FROM_EMAIL', default='WasteWorth <no-reply@wasteworth.com>')
EMAIL_TIMEOUT = config('EMAIL_TIMEOUT', default=120, cast=int)


# ===================================================================
# REDIS & CACHING
# ===================================================================

REDIS_HOST = config('REDIS_HOST')
REDIS_PORT = config('REDIS_PORT', cast=int)
REDIS_PASSWORD = config('REDIS_PASSWORD')

CACHES = {
    'default': {
        'BACKEND': 'django_redis.cache.RedisCache',
        'LOCATION': f"redis://{REDIS_HOST}:{REDIS_PORT}/1",
        'OPTIONS': {
            'CLIENT_CLASS': 'django_redis.client.DefaultClient',
            'PASSWORD': REDIS_PASSWORD,
            'SOCKET_CONNECT_TIMEOUT': 5,
            'SOCKET_TIMEOUT': 5,
            'RETRY_ON_TIMEOUT': True,
            'CONNECTION_POOL_KWARGS': {
                'max_connections': 50,
                'retry_on_timeout': True,
                'health_check_interval': 30,
            },
            'IGNORE_EXCEPTIONS': False,  # Fail loudly in production
        },
        'TIMEOUT': 300,
    }
}

AXES_CACHE = 'default'

# Redis Queue Configuration
RQ_QUEUES = {
    'default': {
        'HOST': REDIS_HOST,
        'PORT': REDIS_PORT,
        'DB': 0,
        'PASSWORD': REDIS_PASSWORD,
        'DEFAULT_TIMEOUT': 360,
    },
    'high': {
        'HOST': REDIS_HOST,
        'PORT': REDIS_PORT,
        'DB': 0,
        'PASSWORD': REDIS_PASSWORD,
        'DEFAULT_TIMEOUT': 500,
    },
    'low': {
        'HOST': REDIS_HOST,
        'PORT': REDIS_PORT,
        'DB': 0,
        'PASSWORD': REDIS_PASSWORD,
        'DEFAULT_TIMEOUT': 500,
    }
}


# ===================================================================
# LOGGING CONFIGURATION
# ===================================================================

LOGGING = {
    'version': 1,
    'disable_existing_loggers': False,
    'formatters': {
        'verbose': {
            'format': '[{levelname}] {asctime} {name} - {message}',
            'style': '{',
            'datefmt': '%Y-%m-%d %H:%M:%S',
        },
        'simple': {
            'format': '{levelname} {message}',
            'style': '{',
        },
    },
    'filters': {
        'sensitive_data_filter': {
            '()': 'utils.logging.SensitiveDataFilter',
        },
    },
    'handlers': {
        'console': {
            'level': 'INFO',
            'class': 'logging.StreamHandler',
            'formatter': 'verbose',
            'filters': ['sensitive_data_filter'],
        },
        'file_api': {
            'level': 'INFO',
            'class': 'logging.handlers.RotatingFileHandler',
            'filename': LOGS_DIR / 'api.log',
            'maxBytes': 1024 * 1024 * 10,  # 10 MB
            'backupCount': 5,
            'formatter': 'verbose',
            'filters': ['sensitive_data_filter'],
        },
        'file_errors': {
            'level': 'ERROR',
            'class': 'logging.handlers.RotatingFileHandler',
            'filename': LOGS_DIR / 'errors.log',
            'maxBytes': 1024 * 1024 * 10,  # 10 MB
            'backupCount': 5,
            'formatter': 'verbose',
            'filters': ['sensitive_data_filter'],
        },
    },
    'loggers': {
        'api': {
            'handlers': ['console', 'file_api', 'file_errors'],
            'level': 'INFO',
            'propagate': False,
        },
        'django': {
            'handlers': ['console', 'file_errors'],
            'level': 'WARNING',
        },
        'django.security': {
            'handlers': ['console', 'file_errors'],
            'level': 'WARNING',
        },
    },
}


# ===================================================================
# FRONTEND & SERVICES
# ===================================================================

FRONTEND_URL = config('FRONTEND_URL')
NODE_SERVICE_URL = config('NODE_SERVICE_URL')
INTERNAL_API_KEY = config('INTERNAL_API_KEY')


# ===================================================================
# PAYSTACK CONFIGURATION (Live Keys)
# ===================================================================

PAYSTACK_SECRET_KEY = config('PAYSTACK_SECRET_KEY')
PAYSTACK_PUBLIC_KEY = config('PAYSTACK_PUBLIC_KEY')
PAYSTACK_WEBHOOK_SECRET = config('PAYSTACK_WEBHOOK_SECRET')
PAYSTACK_CALLBACK_URL = config(
    'PAYSTACK_CALLBACK_URL',
    default=f'{FRONTEND_URL}/payment/callback'
)

# Validate Paystack keys are live keys (not test keys)
if PAYSTACK_SECRET_KEY.startswith('sk_test_'):
    raise ValueError(
        "Production is using Paystack TEST secret key! "
        "Update PAYSTACK_SECRET_KEY to use live key (sk_live_...)."
    )

if PAYSTACK_PUBLIC_KEY.startswith('pk_test_'):
    raise ValueError(
        "Production is using Paystack TEST public key! "
        "Update PAYSTACK_PUBLIC_KEY to use live key (pk_live_...)."
    )


# ===================================================================
# CLOUDINARY CONFIGURATION
# ===================================================================

CLOUDINARY_URL = config('CLOUDINARY_URL')

import cloudinary
cloudinary.config(cloudinary_url=CLOUDINARY_URL)

# Default file storage (Cloudinary)
DEFAULT_FILE_STORAGE = 'cloudinary_storage.storage.MediaCloudinaryStorage'


# ===================================================================
# STATIC FILES (Production)
# ===================================================================

STATIC_ROOT = BASE_DIR / 'staticfiles'
STATICFILES_STORAGE = 'django.contrib.staticfiles.storage.ManifestStaticFilesStorage'


# ===================================================================
# OPTIONAL: MONITORING & ERROR TRACKING
# ===================================================================

# Uncomment if using Sentry for error tracking
# import sentry_sdk
# from sentry_sdk.integrations.django import DjangoIntegration
#
# sentry_sdk.init(
#     dsn=config('SENTRY_DSN', default=''),
#     integrations=[DjangoIntegration()],
#     traces_sample_rate=0.1,  # 10% of transactions for performance monitoring
#     send_default_pii=False,  # Don't send personally identifiable information
#     environment='production',
# )


# ===================================================================
# PRODUCTION VALIDATION
# ===================================================================

# Validate all critical environment variables are set
REQUIRED_ENV_VARS = [
    'SECRET_KEY',
    'ALLOWED_HOSTS',
    'DATABASE_PASSWORD',
    'REDIS_PASSWORD',
    'EMAIL_HOST_USER',
    'EMAIL_HOST_PASSWORD',
    'PAYSTACK_SECRET_KEY',
    'PAYSTACK_PUBLIC_KEY',
    'CLOUDINARY_URL',
    'INTERNAL_API_KEY',
]

missing_vars = []
for var in REQUIRED_ENV_VARS:
    try:
        value = config(var)
        if not value or value == '':
            missing_vars.append(var)
    except:
        missing_vars.append(var)

if missing_vars:
    raise ValueError(
        f"Production environment validation failed! "
        f"Missing required environment variables: {', '.join(missing_vars)}"
    )
