from wallet.models import Wallet, WalletTransaction
from rest_framework import serializers


REDEMPTION_CHOICES = [
        ('voucher', 'Voucher'),
        ('airtime', 'Airtime'),
    ]


class WalletSerializer(serializers.ModelSerializer):
    class Meta:
        model = Wallet
        fields = ['wallet_id', 'user', 'balance', 'points', 'updated_at']


class WalletTransactionSerializer(serializers.ModelSerializer):
    class Meta:
        model = WalletTransaction
        fields = [
            'transaction_id',
            'user',
            'transaction_type',
            'amount',
            'points',
            'payment_method',
            'status',
            'created_at'
        ]


class RedemptionOptionSerializer(serializers.Serializer):
    
    redemption_type = serializers.ChoiceField(choices=REDEMPTION_CHOICES)
    points = serializers.IntegerField(min_value=100, required=True, help_text="Minimum 100 points required for redemption")

    def validate(self, data):
        redemption_type = data.get('redemption_type')
        points = data.get('points')
   
        if redemption_type in ['voucher', 'airtime'] and points is None:
            raise serializers.ValidationError("Points are required for voucher or airtime redemption.")
        return data
    
class RedeemPointsSerializer(serializers.Serializer):
        option = serializers.ChoiceField(choices=REDEMPTION_CHOICES)
        points = serializers.IntegerField(min_value=100, required=True, help_text="Minimum 100 points required for redemption")

        def validate(self, data):
            option = data.get('option')
            points = data.get('points')
       
            if option in ['voucher', 'airtime'] and points is None:
                raise serializers.ValidationError("Points are required for voucher or airtime redemption.")
            return data
        
class RedemptionHistorySerializer(serializers.ModelSerializer):
        class Meta:
            model = WalletTransaction
            fields = [
                'transaction_id',
                'transaction_type',
                'points',
                'status',
                'created_at'
            ]

