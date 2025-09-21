from django.db import models
from django.conf import settings
import uuid


class Notification(models.Model):

    class Meta:
        db_table = 'notifications'
    TYPE_CHOICES = [
        ('pickup', 'Pickup'),
        ('reward', 'Reward'),
        ('marketplace', 'Marketplace'),
        ('general', 'General'),
    ]

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    user_id = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.CASCADE, related_name='notifications')
    type = models.CharField(max_length=20, choices=TYPE_CHOICES)
    message = models.TextField()
    is_read = models.BooleanField(default=False)
    created_at = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return f"Notification for {self.user_id.name or self.user_id.email}: {self.type}"
