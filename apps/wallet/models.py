from django.db import models
from django.conf import settings
import uuid


class Wallet(models.Model):
    class Meta:
        db_table = 'wallets'
        
    wallet_id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    user = models.OneToOneField(settings.AUTH_USER_MODEL, on_delete=models.CASCADE, related_name='wallet')
    balance = models.DecimalField(max_digits=10, decimal_places=2, default=0.00, help_text="Cash balance (Naira, Cedis, etc.)")
    currency = models.CharField(max_length=3, default='NGN', help_text="Currency code (NGN, GHS, etc.)")
    points = models.IntegerField(default=0, help_text="Eco-points earned via referrals and recycling activity")
    is_active = models.BooleanField(default=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    def __str__(self):
        return f"Wallet for {self.user.name or self.user.email} - Balance: {self.balance} {self.currency}"


class WalletTransaction(models.Model):
    class Meta:
        db_table = 'wallet_transactions'
        ordering = ['-created_at']
        indexes = [
            # For wallet transaction history queries (most common)
            models.Index(fields=['wallet', '-created_at'], name='wallet_created_idx'),

            # For user transaction history queries
            models.Index(fields=['user', '-created_at'], name='user_created_idx'),

            # For wallet + type filtering (credits, debits, etc.)
            models.Index(fields=['wallet', 'transaction_type', '-created_at'], name='wallet_type_idx'),

            # For counting user's activity/referral rewards
            models.Index(fields=['user', 'transaction_type'], name='user_type_idx'),

            # For admin queries on pending/failed transactions
            models.Index(fields=['status', '-created_at'], name='status_created_idx'),
        ]

    TRANSACTION_TYPE_CHOICES = [
        ('credit', 'Credit'),
        ('debit', 'Debit'),
        ('payout', 'Payout'),
        ('referral_reward', 'Referral Reward'),
        ('activity_reward', 'Activity Reward'),
        ('redeem', 'Redeem Points'),
        ('deposit', 'Deposit'),
        ('withdrawal', 'Withdrawal'),
        ('refund', 'Refund'),
    ]

    PAYMENT_METHOD_CHOICES = [
        ('bank', 'Bank Transfer'),
        ('mobileMoney', 'Mobile Money'),
        ('airtime', 'Airtime'),
        ('voucher', 'Voucher'),
        ('system', 'System Credit'),
        ('card', 'Card Payment'),
        ('referral_reward', 'Referral Reward'),
        ('activity_reward', 'Activity Reward'),
        ('redeem', 'Redeem Points'),
    ]

    STATUS_CHOICES = [
        ('pending', 'Pending'),
        ('processing', 'Processing'),
        ('success', 'Success'),
        ('failed', 'Failed'),
        ('cancelled', 'Cancelled'),
    ]

    transaction_id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    wallet = models.ForeignKey(Wallet, on_delete=models.CASCADE, related_name='transactions', null=True, blank=True)
    user = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.CASCADE, related_name='wallet_transactions')
    transaction_type = models.CharField(max_length=20, choices=TRANSACTION_TYPE_CHOICES)
    amount = models.DecimalField(max_digits=10, decimal_places=2, null=True, blank=True, help_text="Amount in currency")
    points = models.IntegerField(null=True, blank=True, help_text="Points involved in transaction")
    currency = models.CharField(max_length=3, default='NGN')
    description = models.CharField(max_length=255, blank=True)
    reference = models.CharField(max_length=100, unique=True, blank=True, help_text="External reference number")
    payment_method = models.CharField(max_length=20, choices=PAYMENT_METHOD_CHOICES)
    status = models.CharField(max_length=20, choices=STATUS_CHOICES, default='pending')
    metadata = models.JSONField(null=True, blank=True, help_text="Additional transaction data")
    created_at = models.DateTimeField(auto_now_add=True)

    def save(self, *args, **kwargs):
        if not self.reference:
            self.reference = f"WW{self.transaction_id.hex[:8].upper()}"
        super().save(*args, **kwargs)

    def __str__(self):
        return f"{self.transaction_type.title()} - {self.amount or self.points} for {self.user.name or self.user.email}"



