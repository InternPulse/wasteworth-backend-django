from django.db import models
from django.conf import settings
import uuid


class Payment(models.Model):
    """
    Tracks payment transactions via Paystack.
    One-to-one with MarketplaceListing.
    """

    class Meta:
        db_table = 'payments'
        indexes = [
            models.Index(fields=['paystack_reference'], name='payment_ref_idx'),
            models.Index(fields=['status', '-created_at'], name='payment_status_idx'),
            models.Index(fields=['payer', '-created_at'], name='payment_payer_idx'),
        ]

    PAYMENT_STATUS_CHOICES = [
        ('pending', 'Pending'),
        ('processing', 'Processing'),
        ('success', 'Success'),
        ('failed', 'Failed'),
        ('refunded', 'Refunded'),
    ]

    PAYMENT_PROVIDER_CHOICES = [
        ('paystack', 'Paystack'),
        ('manual', 'Manual'),  # For testing
    ]

    # Primary keys
    payment_id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    marketplace_listing = models.OneToOneField(
        'marketplace.MarketplaceListing',
        on_delete=models.CASCADE,
        related_name='payment'
    )

    # Payer info
    payer = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.CASCADE,
        related_name='payments_made'
    )

    # Payment details
    amount = models.DecimalField(max_digits=10, decimal_places=2)
    currency = models.CharField(max_length=3, default='NGN')
    payment_method = models.CharField(max_length=50, blank=True)  # card, bank, ussd

    # Paystack references
    paystack_reference = models.CharField(max_length=100, unique=True)
    paystack_access_code = models.CharField(max_length=100, blank=True)
    paystack_authorization_url = models.URLField(blank=True)

    # Status tracking
    status = models.CharField(max_length=20, choices=PAYMENT_STATUS_CHOICES, default='pending')
    payment_provider = models.CharField(max_length=20, choices=PAYMENT_PROVIDER_CHOICES, default='paystack')

    # Verification
    is_verified = models.BooleanField(default=False)
    verified_at = models.DateTimeField(null=True, blank=True)

    # Webhook data
    paystack_response = models.JSONField(null=True, blank=True)
    webhook_received_at = models.DateTimeField(null=True, blank=True)

    # Retry handling
    retry_count = models.IntegerField(default=0)
    last_error = models.TextField(blank=True)

    # Timestamps
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    def __str__(self):
        return f"Payment {self.payment_id} - {self.amount} {self.currency} ({self.status})"


class Payout(models.Model):
    """
    Tracks payout transfers to disposers via Paystack Transfer API.
    Created when escrow is released.
    """

    class Meta:
        db_table = 'payouts'
        indexes = [
            models.Index(fields=['paystack_transfer_code'], name='payout_transfer_idx'),
            models.Index(fields=['status', '-created_at'], name='payout_status_idx'),
            models.Index(fields=['recipient', '-created_at'], name='payout_recipient_idx'),
        ]

    PAYOUT_STATUS_CHOICES = [
        ('pending', 'Pending'),
        ('processing', 'Processing'),
        ('success', 'Success'),
        ('failed', 'Failed'),
        ('reversed', 'Reversed'),
    ]

    # Primary keys
    payout_id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    payment = models.OneToOneField(Payment, on_delete=models.CASCADE, related_name='payout')

    # Recipient info
    recipient = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.CASCADE,
        related_name='payouts_received'
    )
    recipient_account_number = models.CharField(max_length=20, blank=True)
    recipient_bank_code = models.CharField(max_length=10, blank=True)
    recipient_account_name = models.CharField(max_length=255, blank=True)

    # Payout details
    amount = models.DecimalField(max_digits=10, decimal_places=2)
    platform_fee = models.DecimalField(max_digits=10, decimal_places=2, default=0.00)
    net_amount = models.DecimalField(max_digits=10, decimal_places=2)  # amount - platform_fee
    currency = models.CharField(max_length=3, default='NGN')

    # Paystack references
    paystack_transfer_code = models.CharField(max_length=100, unique=True, null=True, blank=True)
    paystack_transfer_id = models.CharField(max_length=100, null=True, blank=True)

    # Status tracking
    status = models.CharField(max_length=20, choices=PAYOUT_STATUS_CHOICES, default='pending')

    # Verification
    is_completed = models.BooleanField(default=False)
    completed_at = models.DateTimeField(null=True, blank=True)

    # Webhook data
    paystack_response = models.JSONField(null=True, blank=True)

    # Retry handling
    retry_count = models.IntegerField(default=0)
    last_error = models.TextField(blank=True)

    # Timestamps
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    def __str__(self):
        return f"Payout {self.payout_id} - {self.net_amount} {self.currency} to {self.recipient.name}"
