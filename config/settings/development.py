"""
Development settings for WasteWorth project.

Use this for local development. Settings are optimized for ease of use and debugging.
Security features are relaxed, and external services use mock/local alternatives where possible.
"""

from .base import *
from decouple import Config, RepositoryEnv

# Try to load .env.dev file, fallback to environment variables
try:
    config = Config(RepositoryEnv(str(BASE_DIR / '.env.dev')))
except:
    from decouple import config


# ===================================================================
# CORE DJANGO SETTINGS
# ===================================================================

# Debug mode is always enabled in development
DEBUG = True

# Secret key can use an insecure default in development
SECRET_KEY = config(
    'SECRET_KEY',
    default='django-insecure-dev-key-change-in-production-!@#$%^&*()'
)

# Allow all hosts in development for convenience
ALLOWED_HOSTS = ['*']


# ===================================================================
# DATABASE CONFIGURATION
# ===================================================================

# Use SQLite for local development (no external dependencies needed)
DATABASES = {
    'default': {
        'ENGINE': 'django.db.backends.sqlite3',
        'NAME': BASE_DIR / 'db.sqlite3',
    }
}

# Optional: Uncomment to use PostgreSQL locally
# DATABASES = {
#     'default': {
#         'ENGINE': 'django.db.backends.postgresql',
#         'NAME': config('DATABASE_NAME', default='wasteworth_dev'),
#         'USER': config('DATABASE_USER', default='postgres'),
#         'PASSWORD': config('DATABASE_PASSWORD', default='postgres'),
#         'HOST': config('DATABASE_HOST', default='localhost'),
#         'PORT': config('DATABASE_PORT', default='5432'),
#         'CONN_MAX_AGE': 0,  # Don't reuse connections in dev for easier debugging
#     }
# }


# ===================================================================
# SECURITY SETTINGS (Disabled in Development)
# ===================================================================

# No HTTPS enforcement in development
SECURE_SSL_REDIRECT = False
SECURE_HSTS_SECONDS = 0
SECURE_HSTS_INCLUDE_SUBDOMAINS = False
SECURE_HSTS_PRELOAD = False

# Cookies don't need to be secure over HTTP
SESSION_COOKIE_SECURE = False
CSRF_COOKIE_SECURE = False


# ===================================================================
# CORS CONFIGURATION
# ===================================================================

# Allow common local development origins
CORS_ALLOWED_ORIGINS = [
    "http://localhost:3000",      # React default
    "http://127.0.0.1:3000",
    "http://localhost:3001",      # Alternative React port
    "http://127.0.0.1:3001",
    "http://localhost:5173",      # Vite default
    "http://127.0.0.1:5173",
    "http://localhost:8080",      # Vue CLI default
    "http://127.0.0.1:8080",
]

# Can override with environment variable if needed
CORS_ORIGINS_ENV = config('CORS_ALLOWED_ORIGINS', default='')
if CORS_ORIGINS_ENV:
    CORS_ALLOWED_ORIGINS = [s.strip() for s in CORS_ORIGINS_ENV.split(',') if s.strip()]


# ===================================================================
# EMAIL CONFIGURATION
# ===================================================================

# Print emails to console instead of sending them
EMAIL_BACKEND = 'django.core.mail.backends.console.EmailBackend'
DEFAULT_FROM_EMAIL = 'dev@wasteworth.local'

# If you want to test real email sending in development, uncomment:
# EMAIL_BACKEND = 'utils.email_backend.SMTPBackendWithTimeout'
# EMAIL_HOST = config('EMAIL_HOST', default='smtp.gmail.com')
# EMAIL_PORT = config('EMAIL_PORT', default=587, cast=int)
# EMAIL_USE_TLS = True
# EMAIL_USE_SSL = False
# EMAIL_HOST_USER = config('EMAIL_HOST_USER', default='')
# EMAIL_HOST_PASSWORD = config('EMAIL_HOST_PASSWORD', default='')
# EMAIL_TIMEOUT = 120


# ===================================================================
# REDIS & CACHING
# ===================================================================

# Use local Redis if available, fallback to dummy cache
REDIS_HOST = config('REDIS_HOST', default='localhost')
REDIS_PORT = config('REDIS_PORT', default=6379, cast=int)
REDIS_PASSWORD = config('REDIS_PASSWORD', default='')

try:
    # Try to use Redis for caching
    CACHES = {
        'default': {
            'BACKEND': 'django_redis.cache.RedisCache',
            'LOCATION': f"redis://{REDIS_HOST}:{REDIS_PORT}/1",
            'OPTIONS': {
                'CLIENT_CLASS': 'django_redis.client.DefaultClient',
                'PASSWORD': REDIS_PASSWORD,
                'SOCKET_CONNECT_TIMEOUT': 5,
                'SOCKET_TIMEOUT': 5,
                'IGNORE_EXCEPTIONS': True,  # Fail gracefully if Redis unavailable
            },
            'TIMEOUT': 300,
        }
    }
except:
    # Fallback to dummy cache if Redis is not available
    CACHES = {
        'default': {
            'BACKEND': 'django.core.cache.backends.dummy.DummyCache',
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

# Simple console logging for development
LOGGING = {
    'version': 1,
    'disable_existing_loggers': False,
    'formatters': {
        'simple': {
            'format': '[{levelname}] {message}',
            'style': '{',
        },
        'verbose': {
            'format': '[{levelname}] {asctime} {name} - {message}',
            'style': '{',
            'datefmt': '%Y-%m-%d %H:%M:%S',
        },
    },
    'handlers': {
        'console': {
            'level': 'DEBUG',
            'class': 'logging.StreamHandler',
            'formatter': 'verbose',
        },
    },
    'root': {
        'handlers': ['console'],
        'level': 'INFO',
    },
    'loggers': {
        'django': {
            'handlers': ['console'],
            'level': 'INFO',
            'propagate': False,
        },
        'api': {
            'handlers': ['console'],
            'level': 'DEBUG',
            'propagate': False,
        },
    },
}


# ===================================================================
# FRONTEND & SERVICES
# ===================================================================

FRONTEND_URL = config('FRONTEND_URL', default='http://localhost:3000')
NODE_SERVICE_URL = config('NODE_SERVICE_URL', default='http://localhost:3000')
INTERNAL_API_KEY = config('INTERNAL_API_KEY', default='dev-internal-key')


# ===================================================================
# PAYSTACK CONFIGURATION (Test Keys)
# ===================================================================

PAYSTACK_SECRET_KEY = config('PAYSTACK_SECRET_KEY', default='sk_test_your_test_key')
PAYSTACK_PUBLIC_KEY = config('PAYSTACK_PUBLIC_KEY', default='pk_test_your_test_key')
PAYSTACK_WEBHOOK_SECRET = config('PAYSTACK_WEBHOOK_SECRET', default='')
PAYSTACK_CALLBACK_URL = config(
    'PAYSTACK_CALLBACK_URL',
    default=f'{FRONTEND_URL}/payment/callback'
)


# ===================================================================
# CLOUDINARY CONFIGURATION
# ===================================================================

# Cloudinary configuration (optional in development)
CLOUDINARY_URL = config('CLOUDINARY_URL', default='')

if CLOUDINARY_URL:
    import cloudinary
    cloudinary.config(cloudinary_url=CLOUDINARY_URL)
else:
    # Use local file storage if Cloudinary not configured
    MEDIA_URL = '/media/'
    MEDIA_ROOT = BASE_DIR / 'media'


# ===================================================================
# DEVELOPMENT TOOLS
# ===================================================================

# Uncomment to enable Django Debug Toolbar
# INSTALLED_APPS += ['debug_toolbar']
# MIDDLEWARE.insert(0, 'debug_toolbar.middleware.DebugToolbarMiddleware')
# INTERNAL_IPS = ['127.0.0.1', 'localhost']
