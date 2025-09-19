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

    listing_id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    user_id = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.CASCADE, related_name='listings')
    collector_id = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.SET_NULL, null=True, blank=True, related_name='collected_listings')
    waste_type = models.CharField(max_length=20, choices=WASTE_TYPE_CHOICES, default='plastic')
    quantity = models.FloatField()
    status = models.CharField(max_length=20, choices=STATUS_CHOICES, default='pending')
    reward_estimate = models.DecimalField(max_digits=10, decimal_places=2)
    final_reward = models.DecimalField(max_digits=10, decimal_places=2, null=True, blank=True)
    pickup_location = models.JSONField()  # { "lat": float, "lng": float }
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    def __str__(self):
        return f"Listing {self.listing_id} - {self.waste_type} by {self.user_id.name or self.user_id.email}"


class MarketplaceListing(models.Model):
    class Meta:
        db_table = 'marketplace_listings'
    WASTE_TYPE_CHOICES = [
        ('plastic', 'Plastic'),
        ('glass', 'Glass'),
        ('paper', 'Paper'),
    ]

    ESCROW_STATUS_CHOICES = [
        ('pending', 'Pending'),
        ('locked', 'Locked'),
        ('released', 'Released'),
        ('cancelled', 'Cancelled'),
    ]

    marketplace_id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    pickup_id = models.ForeignKey(Listing, on_delete=models.CASCADE, related_name='marketplace_listings')
    recycler_id = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.CASCADE, related_name='marketplace_purchases')
    waste_type = models.CharField(max_length=20, choices=WASTE_TYPE_CHOICES)
    quantity_kg = models.FloatField()
    price = models.DecimalField(max_digits=10, decimal_places=2)
    escrow_status = models.CharField(max_length=20, choices=ESCROW_STATUS_CHOICES, default='pending')
    created_at = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return f"Marketplace: {self.pickup_id.listing_id} - {self.waste_type} {self.quantity_kg}kg by {self.recycler_id.name or self.recycler_id.email}"
