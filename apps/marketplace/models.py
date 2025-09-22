from django.db import models
from django.conf import settings
from apps.listings.models import Listing
import uuid

# Create your models here.




class MarketplaceListing(models.Model):
    class Meta:
        db_table = 'marketplace_listings'

    ESCROW_STATUS_CHOICES = [
        ('pending', 'Pending'),
        ('locked', 'Locked'),
        ('released', 'Released'),
        ('cancelled', 'Cancelled'),
    ]

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    listing_id = models.ForeignKey(Listing, on_delete=models.CASCADE, related_name='marketplace_listings')
    recycler_id = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.CASCADE, null=True, blank=True, related_name='marketplace_purchases')
    price = models.DecimalField(max_digits=10, decimal_places=2)
    escrow_status = models.CharField(max_length=20, choices=ESCROW_STATUS_CHOICES, default='pending')
    created_at = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        recycler_name = self.recycler_id.name if self.recycler_id else "Unassigned"
        return f"Marketplace: {self.listing_id.id} - {self.listing_id.user_id.name} → {recycler_name} (${self.price})"