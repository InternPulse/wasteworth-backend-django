from rest_framework import serializers
from django.contrib.auth import get_user_model
from .models import Wallet, WalletTransaction

User = get_user_model()


class WalletSerializer(serializers.ModelSerializer):
    """
    Serializer for wallet balance and basic wallet information.
    Follows the same read-only pattern as UserProfileSerializer.
    """
    wallet_id = serializers.UUIDField(source='wallet_id', read_only=True)
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
    transaction_id = serializers.UUIDField(source='transaction_id', read_only=True)
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
        Similar to UserSignupSerializer and other existing serializers.
        """
        transaction_type = data.get('transaction_type')
        amount = data.get('amount')
        points = data.get('points')
        
        # Ensure either amount or points is provided
        if not amount and not points:
            raise serializers.ValidationError({
                'amount': ['Either amount or points must be provided for the transaction.']
            })
        
        # Validate transaction type specific rules
        if transaction_type in ['debit', 'withdrawal', 'payout'] and amount and amount <= 0:
            raise serializers.ValidationError({
                'amount': ['Amount must be positive for debit transactions.']
            })
        
        if transaction_type in ['credit', 'deposit', 'referral_reward'] and amount and amount <= 0:
            raise serializers.ValidationError({
                'amount': ['Amount must be positive for credit transactions.']
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
        """Validation for transaction creation"""
        transaction_type = data.get('transaction_type')
        amount = data.get('amount')
        points = data.get('points')
        payment_method = data.get('payment_method')
        
        # Ensure either amount or points is provided
        if not amount and not points:
            raise serializers.ValidationError(
                "Either amount or points must be provided for the transaction."
            )
        
        # Validate payment method for amount transactions
        if amount and not payment_method:
            raise serializers.ValidationError({
                'payment_method': ['Payment method is required for monetary transactions.']
            })
        
        # Points transactions use system credit
        if points and not amount:
            data['payment_method'] = 'system'
        
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