from django.contrib import admin
from .models import ContactMessage


@admin.register(ContactMessage)
class ContactMessageAdmin(admin.ModelAdmin):
    """
    Admin interface for ContactMessage model.
    """
    list_display = ['full_name', 'email', 'heard_about', 'created_at']
    list_filter = ['created_at', 'heard_about']
    search_fields = ['first_name', 'last_name', 'email', 'message']
    readonly_fields = ['created_at']
    ordering = ['-created_at']

    fieldsets = (
        ('Contact Information', {
            'fields': ('first_name', 'last_name', 'email', 'heard_about')
        }),
        ('Message', {
            'fields': ('message',)
        }),
        ('Metadata', {
            'fields': ('created_at',)
        }),
    )
