"""
URL configuration for config project.
"""
from django.contrib import admin
from django.urls import path, include
from rest_framework_simplejwt.views import TokenRefreshView
from apps.core.views import health_check, api_root

urlpatterns = [
    # Health check endpoint (for monitoring services like Render)
    path('', health_check, name='health_check'),
    path('health/', health_check, name='health_check_alias'),

    # API root
    path('api/v1/', api_root, name='api_root'),

    # Admin
    path('admin/', admin.site.urls),

    # API endpoints
    path('api/v1/wallet/', include('apps.wallet.urls')),
    path('api/v1/users/', include('apps.users.urls')),
    path('api/v1/otp/', include('apps.otp.urls')),
    path('api/v1/contact/', include('apps.contact.urls')),
    path('api/v1/payments/', include('apps.payments.urls')),

    # JWT Token refresh endpoint
    path('api/v1/auth/token/refresh/', TokenRefreshView.as_view(), name='token_refresh'),
]
