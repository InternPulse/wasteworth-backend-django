from django.db import models
from django.conf import settings
from apps.listings.models import Listing
import uuid

# Create your models here.




class MarketplaceListing(models.Model):
    class Meta:
        db_table = 'marketplace_listings'
        indexes = [
            models.Index(fields=['escrow_status', '-created_at'], name='mp_escrow_idx'),
        ]

    ESCROW_STATUS_CHOICES = [
        ('pending', 'Pending'),
        ('payment_initiated', 'Payment Initiated'),
        ('locked', 'Locked'),
        ('item_released', 'Item Released'),
        ('confirmed', 'Confirmed'),
        ('released', 'Released'),
        ('refunded', 'Refunded'),
        ('failed', 'Failed'),
        ('cancelled', 'Cancelled'),
        ('disputed', 'Disputed'),
    ]

    # ============ EXISTING FIELDS ============
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    listing_id = models.ForeignKey(Listing, on_delete=models.CASCADE, related_name='marketplace_listings')
    recycler_id = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.CASCADE, null=True, blank=True, related_name='marketplace_purchases')
    price = models.DecimalField(max_digits=10, decimal_places=2)
    escrow_status = models.CharField(max_length=20, choices=ESCROW_STATUS_CHOICES, default='pending')
    created_at = models.DateTimeField(auto_now_add=True)

    # ============ NEW FIELDS FOR PAYMENT TRACKING ============
    # Timestamp tracking for each state transition
    payment_initiated_at = models.DateTimeField(null=True, blank=True)
    payment_locked_at = models.DateTimeField(null=True, blank=True)
    item_released_at = models.DateTimeField(null=True, blank=True)
    confirmed_at = models.DateTimeField(null=True, blank=True)
    released_at = models.DateTimeField(null=True, blank=True)

    # Confirmation tracking
    disposer_confirmed = models.BooleanField(default=False)
    recycler_confirmed = models.BooleanField(default=False)

    def __str__(self):
        recycler_name = self.recycler_id.name if self.recycler_id else "Unassigned"
        return f"Marketplace: {self.listing_id.id} - {self.listing_id.user_id.name} → {recycler_name} (${self.price})"