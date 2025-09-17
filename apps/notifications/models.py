from django.db import models
from django.conf import settings
import uuid


class Notification(models.Model):
    TYPE_CHOICES = [
        ('pickup', 'Pickup'),
        ('reward', 'Reward'),
        ('marketplace', 'Marketplace'),
        ('general', 'General'),
    ]

    notificationId = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    userId = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.CASCADE, related_name='notifications')
    type = models.CharField(max_length=20, choices=TYPE_CHOICES)
    message = models.TextField()
    isRead = models.BooleanField(default=False)
    createdAt = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return f"Notification for {self.userId.name or self.userId.email}: {self.type}"
