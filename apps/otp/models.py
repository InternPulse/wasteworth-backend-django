from django.db import models
from django.conf import settings
from django.utils import timezone
import uuid






class OTP(models.Model):

    class Meta:
        db_table = 'users_otp'
    PURPOSE_CHOICES = [
        ('signup', 'Signup'),
        ('login', 'Login'),
        ('reset', 'Password Reset'),
    ]

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    user_id = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.CASCADE, related_name='otps')
    hashed_otp = models.CharField(max_length=255)
    purpose = models.CharField(max_length=20, choices=PURPOSE_CHOICES, default='signup')
    used = models.BooleanField(default=False)  # Added field to match database
    expires_at = models.DateTimeField()
    created_at = models.DateTimeField(auto_now_add=True)

    def save(self, *args, **kwargs):
        if not self.expires_at:
            self.expires_at = timezone.now() + timezone.timedelta(minutes=10)
        super().save(*args, **kwargs)

    def is_expired(self):
        return timezone.now() > self.expires_at

    def __str__(self):
        return f"OTP ({self.purpose}) for {self.user_id.name} - {'Used' if self.used else 'Expired' if self.is_expired() else 'Valid'}"