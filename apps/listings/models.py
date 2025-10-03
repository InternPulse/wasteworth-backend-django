from django.db import models
from django.conf import settings
import uuid


class Listing(models.Model):

    class Meta:
        db_table = 'listings'
    WASTE_TYPE_CHOICES = [
        ('plastic', 'Plastic'),
        ('glass', 'Glass'),
        ('paper', 'Paper'),
    ]

    STATUS_CHOICES = [
        ('pending', 'Pending'),
        ('accepted', 'Accepted'),
        ('in-progress', 'In Progress'),
        ('completed', 'Completed'),
        ('cancelled', 'Cancelled'),
    ]

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    user_id = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.CASCADE, related_name='listings')
    collector_id = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.SET_NULL, null=True, blank=True, related_name='listings_to_be_collected')
    title = models.CharField(max_length=255, null=True, blank=True)
    waste_type = models.CharField(max_length=20, choices=WASTE_TYPE_CHOICES, default='plastic')
    quantity = models.FloatField()
    status = models.CharField(max_length=20, choices=STATUS_CHOICES, default='pending')
    reward_estimate = models.DecimalField(max_digits=10, decimal_places=2)
    image_url = models.URLField(max_length=500, null=True, blank=True)
    final_reward = models.DecimalField(max_digits=10, decimal_places=2, null=True, blank=True)
    pickup_location = models.JSONField()
    phone = models.CharField(max_length=20, unique=True, null=True, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    def __str__(self):
        return f"Listing {self.id} - {self.waste_type} by {self.user_id.name or self.user_id.email}"

