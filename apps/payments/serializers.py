from rest_framework import serializers
from .models import Payment, Payout


class PaymentSerializer(serializers.ModelSerializer):
    """Serializer for Payment model"""

    class Meta:
        model = Payment
        fields = [
            'payment_id',
            'marketplace_listing',
            'payer',
            'amount',
            'currency',
            'payment_method',
            'paystack_reference',
            'status',
            'is_verified',
            'verified_at',
            'created_at',
            'updated_at'
        ]
        read_only_fields = [
            'payment_id',
            'is_verified',
            'verified_at',
            'created_at',
            'updated_at'
        ]


class PayoutSerializer(serializers.ModelSerializer):
    """Serializer for Payout model"""

    class Meta:
        model = Payout
        fields = [
            'payout_id',
            'payment',
            'recipient',
            'amount',
            'platform_fee',
            'net_amount',
            'currency',
            'status',
            'is_completed',
            'completed_at',
            'created_at',
            'updated_at'
        ]
        read_only_fields = [
            'payout_id',
            'is_completed',
            'completed_at',
            'created_at',
            'updated_at'
        ]
