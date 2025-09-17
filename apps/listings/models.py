from django.db import models
from django.conf import settings
import uuid


class Listing(models.Model):
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

    listingId = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    userId = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.CASCADE, related_name='listings')
    collectorId = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.SET_NULL, null=True, blank=True, related_name='collected_listings')
    wasteType = models.CharField(max_length=20, choices=WASTE_TYPE_CHOICES, default='plastic')
    quantity = models.FloatField()
    status = models.CharField(max_length=20, choices=STATUS_CHOICES, default='pending')
    rewardEstimate = models.DecimalField(max_digits=10, decimal_places=2)
    finalReward = models.DecimalField(max_digits=10, decimal_places=2, null=True, blank=True)
    pickupLocation = models.JSONField()  # { "lat": float, "lng": float }
    createdAt = models.DateTimeField(auto_now_add=True)
    updatedAt = models.DateTimeField(auto_now=True)

    def __str__(self):
        return f"Listing {self.listingId} - {self.wasteType} by {self.userId.name or self.userId.email}"


class MarketplaceListing(models.Model):
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

    marketplaceId = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    pickupId = models.ForeignKey(Listing, on_delete=models.CASCADE, related_name='marketplace_listings')
    recyclerId = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.CASCADE, related_name='marketplace_purchases')
    wasteType = models.CharField(max_length=20, choices=WASTE_TYPE_CHOICES)
    quantityKg = models.FloatField()
    price = models.DecimalField(max_digits=10, decimal_places=2)
    escrowStatus = models.CharField(max_length=20, choices=ESCROW_STATUS_CHOICES, default='pending')
    createdAt = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return f"Marketplace: {self.pickupId.listingId} - {self.wasteType} {self.quantityKg}kg by {self.recyclerId.name or self.recyclerId.email}"
