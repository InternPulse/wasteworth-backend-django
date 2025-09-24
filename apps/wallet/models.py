from django.db import models
from django.conf import settings
import uuid


class Wallet(models.Model):
    class Meta:
        db_table = 'wallets'
    wallet_id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    user = models.OneToOneField(settings.AUTH_USER_MODEL, on_delete=models.CASCADE, related_name='wallet')
    balance = models.DecimalField(max_digits=10, decimal_places=2, default=0,help_text="Cash balance (Naira, Cedis, etc.)")
    points = models.IntegerField(default=0, help_text="Eco-points earned via referrals and recycling activity") 
    updated_at = models.DateTimeField(auto_now=True)

    def __str__(self):
        return f"Wallet for {self.user.name or self.user.email} - Balance: {self.balance}"


class WalletTransaction(models.Model):

    class Meta:
        db_table = 'wallet_transactions'
    TRANSACTION_TYPE_CHOICES = [
        ('credit', 'Credit'),
        ('debit', 'Debit'),
        ('payout', 'Payout'),
        ('referral_reward', 'Referral Reward'),
        ('activity_reward', 'Activity Reward'),
        ('redeem', 'Redeem Points'),
    ]

    PAYMENT_METHOD_CHOICES = [
        ('bank', 'Bank'),
        ('mobileMoney', 'Mobile Money'),
        ('airtime', 'Airtime'),
        ('voucher', 'Voucher'),
        ('system', 'System Credit'),
    ]

    STATUS_CHOICES = [
        ('pending', 'Pending'),
        ('success', 'Success'),
        ('failed', 'Failed'),
    ]

    transaction_id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    user = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.CASCADE, related_name='wallet_transactions')
    transaction_type = models.CharField(max_length=20, choices=TRANSACTION_TYPE_CHOICES)
    amount = models.DecimalField(max_digits=10, decimal_places=2,null=True,blank=True)
    points = models.IntegerField(null=True, blank=True)
    payment_method = models.CharField(max_length=20, choices=PAYMENT_METHOD_CHOICES)
    status = models.CharField(max_length=20, choices=STATUS_CHOICES, default='pending')
    created_at = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return f"{self.transaction_type} - {self.amount} for {self.user.name or self.user.email}"



