from django.db import models
from django.conf import settings
import uuid





class Referral(models.Model):
    class Meta:
        db_table = 'referrals'
    STATUS_CHOICES = [
        ('pending', 'Pending'),
        ('credited', 'Credited'),
    ]

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    referrer = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.CASCADE, related_name='referrals_made')
    referee = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.CASCADE, related_name='referrals_received')
    referral_reward = models.IntegerField(default=0)
    status = models.CharField(max_length=20, choices=STATUS_CHOICES, default='pending')
    created_at = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return f"Referral: {self.referrer.name or self.referrer.email} → {self.referee.name or self.referee.email}"
