from rest_framework import serializers
from django.contrib.auth import get_user_model
from .models import Wallet, WalletTransaction

User = get_user_model()

# Redemption options - subset of payment methods available for point redemption
REDEMPTION_CHOICES = [
    choice for choice in WalletTransaction.PAYMENT_METHOD_CHOICES
    if choice[0] in ['airtime', 'voucher']
]


class WalletSerializer(serializers.ModelSerializer):
    """
    Serializer for wallet balance and basic wallet information.
    Follows the same read-only pattern as UserProfileSerializer.
    """
    wallet_id = serializers.UUIDField(read_only=True)
    user_name = serializers.CharField(source='user.name', read_only=True)
    user_email = serializers.CharField(source='user.email', read_only=True)
    
    class Meta:
        model = Wallet
        fields = [
            'wallet_id', 'user_name', 'user_email', 'balance', 
            'currency', 'points', 'is_active', 'created_at', 'updated_at'
        ]
        read_only_fields = [
            'wallet_id', 'user_name', 'user_email', 'balance', 
            'currency', 'points', 'is_active', 'created_at', 'updated_at'
        ]


class TransactionSerializer(serializers.ModelSerializer):
    """
    Serializer for wallet transactions with detailed information.
    Supports both read and write operations following project patterns.
    """
    transaction_id = serializers.UUIDField(read_only=True)
    wallet_id = serializers.UUIDField(source='wallet.wallet_id', read_only=True)
    user_name = serializers.CharField(source='user.name', read_only=True)
    user_email = serializers.CharField(source='user.email', read_only=True)
    transaction_type_display = serializers.CharField(source='get_transaction_type_display', read_only=True)
    payment_method_display = serializers.CharField(source='get_payment_method_display', read_only=True)
    status_display = serializers.CharField(source='get_status_display', read_only=True)
    
    class Meta:
        model = WalletTransaction
        fields = [
            'transaction_id', 'wallet_id', 'user_name', 'user_email',
            'transaction_type', 'transaction_type_display',
            'amount', 'points', 'currency', 'description', 'reference',
            'payment_method', 'payment_method_display',
            'status', 'status_display', 'metadata', 'created_at'
        ]
        read_only_fields = [
            'transaction_id', 'wallet_id', 'user_name', 'user_email',
            'transaction_type_display', 'payment_method_display', 
            'status_display', 'reference', 'created_at'
        ]

    def validate(self, data):
        """
        Custom validation following the project's validation patterns.
        Handles both cash (amount) and points transactions with proper validation.
        """
        transaction_type = data.get('transaction_type')
        amount = data.get('amount')
        points = data.get('points')

        # Ensure either amount or points is provided
        if not amount and not points:
            raise serializers.ValidationError({
                'transaction': ['Either amount or points must be provided for the transaction.']
            })

        # Validate amount-based transactions (cash)
        if amount is not None:
            if amount <= 0:
                raise serializers.ValidationError({
                    'amount': ['Amount must be positive for cash transactions.']
                })

        # Validate points-based transactions
        if points is not None:
            if points <= 0:
                raise serializers.ValidationError({
                    'points': ['Points must be positive for points transactions.']
                })

            # Points transactions should use specific transaction types
            points_transaction_types = ['referral_reward', 'activity_reward', 'redeem']
            if transaction_type not in points_transaction_types:
                raise serializers.ValidationError({
                    'transaction_type': [f'Points transactions must use one of: {", ".join(points_transaction_types)}']
                })

        # Validate specific transaction type rules
        if transaction_type in ['referral_reward', 'activity_reward'] and not points:
            raise serializers.ValidationError({
                'points': ['Reward transactions must include points.']
            })

        if transaction_type == 'redeem' and not points:
            raise serializers.ValidationError({
                'points': ['Redeem transactions must include points to redeem.']
            })

        # Cash-only transaction types
        cash_only_types = ['deposit', 'withdrawal', 'payout', 'refund']
        if transaction_type in cash_only_types and not amount:
            raise serializers.ValidationError({
                'amount': [f'{transaction_type.title()} transactions must include a cash amount.']
            })

        return data


class TransactionCreateSerializer(serializers.ModelSerializer):
    """
    Serializer for creating new transactions.
    Follows the same create pattern as UserSignupSerializer.
    """
    
    class Meta:
        model = WalletTransaction
        fields = [
            'transaction_type', 'amount', 'points', 'currency',
            'description', 'payment_method', 'metadata'
        ]

    def validate(self, data):
        """
        Validation for transaction creation with proper points handling.
        Points are the main focus, with cash as secondary.
        """
        transaction_type = data.get('transaction_type')
        amount = data.get('amount')
        points = data.get('points')
        payment_method = data.get('payment_method')

        # Ensure either amount or points is provided
        if not amount and not points:
            raise serializers.ValidationError({
                'transaction': ['Either amount or points must be provided for the transaction.']
            })

        # Validate points transactions (main focus)
        if points is not None:
            if points <= 0:
                raise serializers.ValidationError({
                    'points': ['Points must be positive.']
                })

            # Points transactions should use specific transaction types
            points_transaction_types = ['referral_reward', 'activity_reward', 'redeem']
            if transaction_type not in points_transaction_types:
                raise serializers.ValidationError({
                    'transaction_type': [f'Points transactions must use one of: {", ".join(points_transaction_types)}']
                })

            # Points transactions use system payment method
            data['payment_method'] = 'system'

        # Validate cash transactions
        if amount is not None:
            if amount <= 0:
                raise serializers.ValidationError({
                    'amount': ['Amount must be positive.']
                })

            # Cash transactions require payment method
            if not payment_method:
                raise serializers.ValidationError({
                    'payment_method': ['Payment method is required for cash transactions.']
                })

        # Validate transaction type specific requirements
        if transaction_type in ['referral_reward', 'activity_reward'] and not points:
            raise serializers.ValidationError({
                'points': ['Reward transactions must include points.']
            })

        if transaction_type == 'redeem' and not points:
            raise serializers.ValidationError({
                'points': ['Redeem transactions must include points to redeem.']
            })

        return data

    def create(self, validated_data):
        """
        Create transaction following the project's create patterns.
        Similar to User.create() method in UserSignupSerializer.
        """
        # Get user and wallet from context (set in view)
        user = self.context['request'].user
        wallet = user.wallet
        
        # Create transaction
        transaction = WalletTransaction.objects.create(
            wallet=wallet,
            user=user,
            **validated_data
        )
        
        return transaction


class WalletSummarySerializer(serializers.Serializer):
    """
    Serializer for wallet summary data including recent transactions.
    Similar to dashboard-style serializers in the project.
    """
    wallet = WalletSerializer(read_only=True)
    recent_transactions = TransactionSerializer(many=True, read_only=True)
    total_transactions = serializers.IntegerField(read_only=True)
    total_credits = serializers.DecimalField(max_digits=10, decimal_places=2, read_only=True)
    total_debits = serializers.DecimalField(max_digits=10, decimal_places=2, read_only=True)
    total_points_earned = serializers.IntegerField(read_only=True)
    total_points_redeemed = serializers.IntegerField(read_only=True)


# Transaction filtering serializer for API query parameters
class TransactionFilterSerializer(serializers.Serializer):
    """
    Serializer for transaction filtering parameters.
    Follows the same validation pattern as OTPRequestSerializer.
    """
    transaction_type = serializers.ChoiceField(
        choices=WalletTransaction.TRANSACTION_TYPE_CHOICES,
        required=False,
        help_text="Filter by transaction type"
    )
    payment_method = serializers.ChoiceField(
        choices=WalletTransaction.PAYMENT_METHOD_CHOICES,
        required=False,
        help_text="Filter by payment method"
    )
    status = serializers.ChoiceField(
        choices=WalletTransaction.STATUS_CHOICES,
        required=False,
        help_text="Filter by transaction status"
    )
    date_from = serializers.DateTimeField(
        required=False,
        help_text="Filter transactions from this date"
    )
    date_to = serializers.DateTimeField(
        required=False,
        help_text="Filter transactions until this date"
    )
    min_amount = serializers.DecimalField(
        max_digits=10, decimal_places=2, required=False,
        help_text="Minimum transaction amount"
    )
    max_amount = serializers.DecimalField(
        max_digits=10, decimal_places=2, required=False,
        help_text="Maximum transaction amount"
    )

    def validate(self, data):
        """Validate date range and amount range"""
        date_from = data.get('date_from')
        date_to = data.get('date_to')
        min_amount = data.get('min_amount')
        max_amount = data.get('max_amount')
        
        if date_from and date_to and date_from > date_to:
            raise serializers.ValidationError({
                'date_to': ['End date must be after start date.']
            })
        
        if min_amount and max_amount and min_amount > max_amount:
            raise serializers.ValidationError({
                'max_amount': ['Maximum amount must be greater than minimum amount.']
            })
        
        return data
    
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