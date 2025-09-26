from django.contrib import admin
from .models import Wallet, WalletTransaction


@admin.register(Wallet)
class WalletAdmin(admin.ModelAdmin):
    """
    Admin configuration for Wallet model.
    """
    list_display = ('wallet_id', 'user_display', 'balance', 'currency', 'points', 'is_active', 'updated_at')
    search_fields = ('wallet_id', 'user__email', 'user__name')
    list_filter = ('currency', 'is_active', 'created_at')
    readonly_fields = ('wallet_id', 'created_at', 'updated_at')
    
    fieldsets = (
        ('Wallet Information', {
            'fields': ('wallet_id', 'user', 'balance', 'currency', 'points', 'is_active')
        }),
        ('Timestamps', {
            'fields': ('created_at', 'updated_at'),
            'classes': ('collapse',)
        }),
    )
    
    def user_display(self, obj):
        """Display user's name and email"""
        if obj.user:
            return f"{obj.user.name} ({obj.user.email})"
        return "No user"
    user_display.short_description = 'User'


@admin.register(WalletTransaction)
class WalletTransactionAdmin(admin.ModelAdmin):
    """
    Admin configuration for WalletTransaction model.
    """
    list_display = ('transaction_id', 'user_display', 'transaction_type', 
                   'amount', 'points', 'status', 'payment_method', 'created_at')
    list_filter = ('transaction_type', 'status', 'payment_method', 'created_at')
    search_fields = ('transaction_id', 'user__email', 'reference', 'description')
    readonly_fields = ('transaction_id', 'created_at', 'reference')
    
    fieldsets = (
        ('Transaction Information', {
            'fields': ('transaction_id', 'wallet', 'user', 'transaction_type', 'status')
        }),
        ('Financial Details', {
            'fields': ('amount', 'points', 'currency', 'payment_method')
        }),
        ('Additional Information', {
            'fields': ('description', 'reference', 'metadata')
        }),
        ('Timestamps', {
            'fields': ('created_at',),
            'classes': ('collapse',)
        }),
    )
    
    def user_display(self, obj):
        """Display user's name and email"""
        if obj.user:
            return f"{obj.user.name} ({obj.user.email})"
        return "No user"
    user_display.short_description = 'User'
