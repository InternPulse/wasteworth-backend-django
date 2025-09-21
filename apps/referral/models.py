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
    referrer_id = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.CASCADE, related_name='referrals_made')
    referee_id = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.CASCADE, related_name='referrals_received')
    bonus_amount = models.DecimalField(max_digits=10, decimal_places=2)
    status = models.CharField(max_length=20, choices=STATUS_CHOICES, default='pending')
    created_at = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return f"Referral: {self.referrer_id.name or self.referrer_id.email} → {self.referee_id.name or self.referee_id.email}"
