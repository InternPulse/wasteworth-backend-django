"""
Base settings shared across all environments.

This file contains settings that are identical in development, production, and testing.
Environment-specific settings should go in development.py, production.py, or test.py.
"""

from pathlib import Path
from datetime import timedelta
from decimal import Decimal

# Build paths inside the project like this: BASE_DIR / 'subdir'.
BASE_DIR = Path(__file__).resolve().parent.parent.parent

# Create logs directory if it doesn't exist (for file-based logging)
LOGS_DIR = BASE_DIR / 'logs'
LOGS_DIR.mkdir(exist_ok=True)


# ===================================================================
# APPLICATION DEFINITION
# ===================================================================

INSTALLED_APPS = [
    'axes',
    'django.contrib.admin',
    'django.contrib.auth',
    'django.contrib.contenttypes',
    'django.contrib.sessions',
    'django.contrib.messages',
    'django.contrib.staticfiles',
    'rest_framework',
    'rest_framework_simplejwt',
    'rest_framework_simplejwt.token_blacklist',
    'corsheaders',
    'apps.users',
    'apps.listings',
    'apps.wallet',
    'apps.notifications',
    'apps.otp',
    'apps.referral',
    'apps.marketplace',
    'apps.contact',
    'apps.payments',
    'cloudinary',
    'cloudinary_storage',
]

MIDDLEWARE = [
    'corsheaders.middleware.CorsMiddleware',
    'django.middleware.security.SecurityMiddleware',
    'django.contrib.sessions.middleware.SessionMiddleware',
    'django.middleware.common.CommonMiddleware',
    'django.middleware.csrf.CsrfViewMiddleware',
    'django.contrib.auth.middleware.AuthenticationMiddleware',
    # 'axes.middleware.AxesMiddleware',
    'utils.logging.RequestResponseLoggingMiddleware',
    'django.contrib.messages.middleware.MessageMiddleware',
    'django.middleware.clickjacking.XFrameOptionsMiddleware',
]

ROOT_URLCONF = 'config.urls'

TEMPLATES = [
    {
        'BACKEND': 'django.template.backends.django.DjangoTemplates',
        'DIRS': [],
        'APP_DIRS': True,
        'OPTIONS': {
            'context_processors': [
                'django.template.context_processors.request',
                'django.contrib.auth.context_processors.auth',
                'django.contrib.messages.context_processors.messages',
            ],
        },
    },
]

WSGI_APPLICATION = 'config.wsgi.application'


# ===================================================================
# AUTHENTICATION & SECURITY
# ===================================================================

# Custom User Model
AUTH_USER_MODEL = 'users.User'

AUTHENTICATION_BACKENDS = [
    'axes.backends.AxesStandaloneBackend',
    'django.contrib.auth.backends.ModelBackend',
]

# Password validation
AUTH_PASSWORD_VALIDATORS = [
    {
        'NAME': 'django.contrib.auth.password_validation.UserAttributeSimilarityValidator',
    },
    {
        'NAME': 'django.contrib.auth.password_validation.MinimumLengthValidator',
    },
    {
        'NAME': 'django.contrib.auth.password_validation.CommonPasswordValidator',
    },
    {
        'NAME': 'django.contrib.auth.password_validation.NumericPasswordValidator',
    },
]

# Django-axes Configuration (Brute-force Protection)
AXES_FAILURE_LIMIT = 5  # Lock after 5 failed attempts
AXES_COOLOFF_TIME = timedelta(minutes=30)  # 30-minute lockout
AXES_LOCKOUT_PARAMETERS = ['username', 'ip_address']  # Track by username + IP
AXES_USERNAME_FORM_FIELD = 'email'  # Our login form uses email field
AXES_ENABLE_ADMIN = True  # Enable admin interface
AXES_ONLY_ALLOW_FAILURES_ON_POST = True  # Only count POST requests
AXES_RESET_ON_SUCCESS = True  # Reset counter on successful login
AXES_VERBOSE = True  # Log axes events
AXES_LOCKOUT_MESSAGE = (
    'Too many failed login attempts. Your account has been temporarily locked '
    'for security. Please try again in 30 minutes.'
)

# Cookie Security (base configuration)
SESSION_COOKIE_HTTPONLY = True  # Prevent JavaScript access to session cookies
SESSION_COOKIE_SAMESITE = 'Lax'  # CSRF protection
CSRF_COOKIE_HTTPONLY = True  # Prevent JavaScript access to CSRF tokens
CSRF_COOKIE_SAMESITE = 'Lax'  # CSRF protection

# Browser Security Headers
SECURE_BROWSER_XSS_FILTER = True  # Enable browser XSS protection
SECURE_CONTENT_TYPE_NOSNIFF = True  # Prevent MIME type sniffing
X_FRAME_OPTIONS = 'DENY'  # Prevent clickjacking attacks
SECURE_REFERRER_POLICY = 'same-origin'  # Control referrer information


# ===================================================================
# REST FRAMEWORK & JWT CONFIGURATION
# ===================================================================

REST_FRAMEWORK = {
    'DEFAULT_AUTHENTICATION_CLASSES': (
        'rest_framework_simplejwt.authentication.JWTAuthentication',
    ),
    'DEFAULT_PERMISSION_CLASSES': [
        'rest_framework.permissions.AllowAny'
    ],
    'DEFAULT_RENDERER_CLASSES': [
        'rest_framework.renderers.JSONRenderer',
    ],
    'DEFAULT_PARSER_CLASSES': [
        'rest_framework.parsers.JSONParser',
    ],
    'TEST_REQUEST_DEFAULT_FORMAT': 'json',
    'EXCEPTION_HANDLER': 'utils.error_handler.custom_exception_handler',
}

# JWT Configuration
SIMPLE_JWT = {
    'ACCESS_TOKEN_LIFETIME': timedelta(minutes=60),
    'REFRESH_TOKEN_LIFETIME': timedelta(days=14),
    'ROTATE_REFRESH_TOKENS': True,
    'BLACKLIST_AFTER_ROTATION': True,
    'USER_ID_FIELD': 'id',
    'USER_ID_CLAIM': 'user_id',
}


# ===================================================================
# CORS CONFIGURATION
# ===================================================================

CORS_ALLOW_CREDENTIALS = True

CORS_ALLOW_HEADERS = [
    'accept',
    'accept-encoding',
    'authorization',
    'content-type',
    'dnt',
    'origin',
    'user-agent',
    'x-csrftoken',
    'x-requested-with',
]

CORS_ALLOW_ALL_ORIGINS = False  # Keep security by only allowing specific origins
CORS_ALLOW_METHODS = [
    'DELETE',
    'GET',
    'OPTIONS',
    'PATCH',
    'POST',
    'PUT',
]

CORS_PREFLIGHT_MAX_AGE = 86400  # 24 hours


# ===================================================================
# INTERNATIONALIZATION
# ===================================================================

LANGUAGE_CODE = 'en-us'
TIME_ZONE = 'UTC'
USE_I18N = True
USE_TZ = True


# ===================================================================
# STATIC FILES
# ===================================================================

STATIC_URL = 'static/'


# ===================================================================
# DEFAULT FIELD TYPES
# ===================================================================

DEFAULT_AUTO_FIELD = 'django.db.models.BigAutoField'


# ===================================================================
# PAYSTACK PAYMENT GATEWAY (Constants)
# ===================================================================

# Paystack API endpoints (same for all environments)
PAYSTACK_BASE_URL = 'https://api.paystack.co'
PAYSTACK_INITIALIZE_URL = f'{PAYSTACK_BASE_URL}/transaction/initialize'
PAYSTACK_VERIFY_URL = f'{PAYSTACK_BASE_URL}/transaction/verify'
PAYSTACK_TRANSFER_URL = f'{PAYSTACK_BASE_URL}/transfer'
PAYSTACK_TRANSFER_RECIPIENT_URL = f'{PAYSTACK_BASE_URL}/transferrecipient'

# Platform fee (percentage) - business logic constant
PLATFORM_FEE_PERCENTAGE = Decimal('5.0')  # 5% platform fee
