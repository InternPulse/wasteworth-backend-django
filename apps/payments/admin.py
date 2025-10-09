from django.contrib import admin
from .models import Payment, Payout


@admin.register(Payment)
class PaymentAdmin(admin.ModelAdmin):
    list_display = ['payment_id', 'payer', 'amount', 'status', 'is_verified', 'created_at']
    list_filter = ['status', 'payment_provider', 'is_verified', 'created_at']
    search_fields = ['payment_id', 'paystack_reference', 'payer__email', 'payer__name']
    readonly_fields = ['payment_id', 'paystack_reference', 'created_at', 'updated_at', 'verified_at']
    date_hierarchy = 'created_at'

    fieldsets = (
        ('Basic Info', {
            'fields': ('payment_id', 'marketplace_listing', 'payer', 'amount', 'currency')
        }),
        ('Paystack Details', {
            'fields': ('paystack_reference', 'paystack_access_code', 'paystack_authorization_url', 'payment_method')
        }),
        ('Status', {
            'fields': ('status', 'payment_provider', 'is_verified', 'verified_at')
        }),
        ('Webhook Data', {
            'fields': ('paystack_response', 'webhook_received_at'),
            'classes': ('collapse',)
        }),
        ('Error Tracking', {
            'fields': ('retry_count', 'last_error'),
            'classes': ('collapse',)
        }),
        ('Timestamps', {
            'fields': ('created_at', 'updated_at'),
            'classes': ('collapse',)
        }),
    )


@admin.register(Payout)
class PayoutAdmin(admin.ModelAdmin):
    list_display = ['payout_id', 'recipient', 'net_amount', 'status', 'is_completed', 'created_at']
    list_filter = ['status', 'is_completed', 'created_at']
    search_fields = ['payout_id', 'paystack_transfer_code', 'recipient__email', 'recipient__name']
    readonly_fields = ['payout_id', 'created_at', 'updated_at', 'completed_at']
    date_hierarchy = 'created_at'

    fieldsets = (
        ('Basic Info', {
            'fields': ('payout_id', 'payment', 'recipient')
        }),
        ('Bank Details', {
            'fields': ('recipient_account_number', 'recipient_bank_code', 'recipient_account_name')
        }),
        ('Amount', {
            'fields': ('amount', 'platform_fee', 'net_amount', 'currency')
        }),
        ('Paystack Details', {
            'fields': ('paystack_transfer_code', 'paystack_transfer_id')
        }),
        ('Status', {
            'fields': ('status', 'is_completed', 'completed_at')
        }),
        ('Webhook Data', {
            'fields': ('paystack_response',),
            'classes': ('collapse',)
        }),
        ('Error Tracking', {
            'fields': ('retry_count', 'last_error'),
            'classes': ('collapse',)
        }),
        ('Timestamps', {
            'fields': ('created_at', 'updated_at'),
            'classes': ('collapse',)
        }),
    )
