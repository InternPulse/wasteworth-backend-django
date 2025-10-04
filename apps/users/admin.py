from django.contrib import admin
from django.contrib.auth.admin import UserAdmin as BaseUserAdmin
from django.utils.translation import gettext_lazy as _
from .models import User


@admin.register(User)
class UserAdmin(BaseUserAdmin):
    """
    Custom admin configuration for User model.
    Provides a more appropriate admin interface for our custom User model.
    """
    list_display = ('email', 'name', 'phone', 'role', 'is_verified', 'is_active', 'wallet_balance')
    search_fields = ('name', 'email', 'phone', 'referral_code')
    list_filter = ('is_active', 'is_staff', 'is_verified', 'role', 'created_at')
    ordering = ('email',)
    readonly_fields = ('wallet_balance', 'id', 'created_at', 'updated_at', 'last_login')

    def wallet_balance(self, obj):
        """Display wallet balance from related Wallet model."""
        return f"{obj.wallet.balance} {obj.wallet.currency}" if hasattr(obj, 'wallet') else "No wallet"
    wallet_balance.short_description = 'Wallet Balance'

    fieldsets = (
        (None, {'fields': ('email', 'password')}),
        (_('Personal info'), {'fields': ('name', 'phone', 'address_location')}),
        (_('Wallet & Referrals'), {'fields': ('wallet_balance', 'referral_code', 'referred_by')}),
        (_('Permissions'), {'fields': ('role', 'is_active', 'is_staff', 'is_superuser', 'is_verified')}),
        (_('Important dates'), {'fields': ('last_login', 'created_at', 'updated_at')}),
    )
    
    add_fieldsets = (
        (None, {
            'classes': ('wide',),
            'fields': ('email', 'name', 'phone', 'password1', 'password2', 'role', 'is_staff', 'is_active'),
        }),
    )
