"""
Custom email backend with timeout configuration for Wasteworth application.
"""
from django.core.mail.backends.smtp import EmailBackend as DjangoSMTPBackend
from django.conf import settings


class SMTPBackendWithTimeout(DjangoSMTPBackend):
    """
    Custom SMTP email backend that applies timeout from Django settings.
    Extends Django's default SMTP backend to include timeout configuration.
    """

    def __init__(self, *args, **kwargs):
        # Use EMAIL_TIMEOUT from settings, default to 120 seconds if not set
        timeout = getattr(settings, 'EMAIL_TIMEOUT', 120)
        kwargs.setdefault('timeout', timeout)
        super().__init__(*args, **kwargs)