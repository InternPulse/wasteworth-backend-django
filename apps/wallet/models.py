from django.db import models
from django.conf import settings
import uuid


class Wallet(models.Model):
    walletId = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    userId = models.OneToOneField(settings.AUTH_USER_MODEL, on_delete=models.CASCADE, related_name='wallet')
    balance = models.DecimalField(max_digits=10, decimal_places=2, default=0.00)
    updatedAt = models.DateTimeField(auto_now=True)

    def __str__(self):
        return f"Wallet for {self.userId.name or self.userId.email} - Balance: {self.balance}"


class WalletTransaction(models.Model):
    TRANSACTION_TYPE_CHOICES = [
        ('credit', 'Credit'),
        ('debit', 'Debit'),
        ('payout', 'Payout'),
        ('referral', 'Referral'),
    ]

    PAYMENT_METHOD_CHOICES = [
        ('bank', 'Bank'),
        ('mobileMoney', 'Mobile Money'),
        ('airtime', 'Airtime'),
    ]

    STATUS_CHOICES = [
        ('pending', 'Pending'),
        ('success', 'Success'),
        ('failed', 'Failed'),
    ]

    transactionId = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    userId = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.CASCADE, related_name='wallet_transactions')
    transactionType = models.CharField(max_length=20, choices=TRANSACTION_TYPE_CHOICES)
    amount = models.DecimalField(max_digits=10, decimal_places=2)
    paymentMethod = models.CharField(max_length=20, choices=PAYMENT_METHOD_CHOICES)
    status = models.CharField(max_length=20, choices=STATUS_CHOICES, default='pending')
    createdAt = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return f"{self.transactionType} - {self.amount} for {self.userId.name or self.userId.email}"


class Referral(models.Model):
    STATUS_CHOICES = [
        ('pending', 'Pending'),
        ('credited', 'Credited'),
    ]

    referralId = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    referrerId = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.CASCADE, related_name='referrals_made')
    refereeId = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.CASCADE, related_name='referrals_received')
    bonusAmount = models.DecimalField(max_digits=10, decimal_places=2)
    status = models.CharField(max_length=20, choices=STATUS_CHOICES, default='pending')
    createdAt = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return f"Referral: {self.referrerId.name or self.referrerId.email} → {self.refereeId.name or self.refereeId.email}"
