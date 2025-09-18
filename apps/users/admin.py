from django.contrib import admin
from django.contrib.auth.admin import UserAdmin as BaseUserAdmin
from django.utils.html import format_html
from .models import User, OTP


@admin.register(User)
class UserAdmin(BaseUserAdmin):
    # Fields to display in the admin list view
    list_display = (
        'email', 'name', 'role', 'verification_status', 'phone', 'is_active', 'is_staff', 
        'wallet_balance', 'referral_code', 'created_at'
    )
    
    # Fields that can be used to filter the list
    list_filter = ('role', 'is_verified', 'is_active', 'is_staff', 'is_superuser', 'created_at')
    
    # Fields that can be searched
    search_fields = ('email', 'name', 'phone', 'referral_code')
    
    # Default ordering
    ordering = ('-created_at',)
    
    # Fields to display when editing a user
    fieldsets = (
        (None, {
            'fields': ('email', 'password')
        }),
        ('Personal Info', {
            'fields': ('name', 'phone', 'role', 'is_verified')
        }),
        ('Location', {
            'fields': ('location_lat', 'location_lng', 'address_location'),  # Added address_location
            'classes': ('collapse',)
        }),
        ('Wallet & Referrals', {
            'fields': ('wallet_balance', 'referral_code', 'referred_by')
        }),
        ('Permissions', {
            'fields': ('is_active', 'is_staff', 'is_superuser', 'groups', 'user_permissions'),
            'classes': ('collapse',)
        }),
        ('Important dates', {
            'fields': ('last_login', 'created_at', 'updated_at'),
            'classes': ('collapse',)
        }),
    )
    
    # Fields to display when adding a new user
    add_fieldsets = (
        (None, {
            'classes': ('wide',),
            'fields': ('email', 'name', 'password1', 'password2', 'role'),
        }),
    )
    
    # Read-only fields
    readonly_fields = ('created_at', 'updated_at', 'last_login')
    
    # Remove username from admin since we use email as USERNAME_FIELD
    filter_horizontal = ('groups', 'user_permissions',)
    
    def verification_status(self, obj):
        """Display verification status with color coding"""
        if obj.is_verified:
            return format_html('<span style="color: green; font-weight: bold;">✓ Verified</span>')
        return format_html('<span style="color: red; font-weight: bold;">✗ Unverified</span>')
    verification_status.short_description = 'Verification Status'
    verification_status.admin_order_field = 'is_verified'


@admin.register(OTP)
class OTPAdmin(admin.ModelAdmin):
    # Fields to display in the admin list view
    list_display = (
        'user_email', 'purpose', 'used', 'is_expired_display', 
        'created_at', 'expires_at'
    )
    
    # Fields that can be used to filter the list
    list_filter = ('purpose', 'used', 'created_at')
    
    # Fields that can be searched
    search_fields = ('user__email', 'user__name', 'purpose')
    
    # Default ordering (most recent first)
    ordering = ('-created_at',)
    
    # Read-only fields (OTPs shouldn't be editable)
    readonly_fields = (
        'id', 'user', 'hashed_otp', 'purpose', 'used', 
        'expires_at', 'created_at', 'is_expired_display'
    )
    
    # Fields to display when viewing an OTP
    fields = (
        'id', 'user', 'purpose', 'used', 'is_expired_display',
        'created_at', 'expires_at', 'hashed_otp'
    )
    
    def user_email(self, obj):
        """Display user email in the list view"""
        return obj.user.email
    user_email.short_description = 'User Email'
    user_email.admin_order_field = 'user__email'
    
    def is_expired_display(self, obj):
        """Display expiration status with color coding"""
        if obj.is_expired():
            return format_html('<span style="color: red;">Expired</span>')
        return format_html('<span style="color: green;">Valid</span>')
    is_expired_display.short_description = 'Status'
    
    def has_add_permission(self, request):
        """Disable adding OTPs through admin (they should be generated programmatically)"""
        return False
    
    def has_change_permission(self, request, obj=None):
        """Disable editing OTPs through admin"""
        return False
    
    def has_delete_permission(self, request, obj=None):
        """Allow deleting expired/used OTPs"""
        return True
