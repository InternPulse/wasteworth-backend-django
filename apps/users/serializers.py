from rest_framework import serializers
from django.contrib.auth import get_user_model, authenticate
from django.contrib.auth.password_validation import validate_password
from django.contrib.auth.hashers import check_password,make_password
from django.core.mail import send_mail
from django.conf import settings
from django.utils import timezone
import random
import string
import re
from .models import User
from apps.otp.models import OTP

User = get_user_model()

# ------------------------------
# User Registration & Authentication
# ------------------------------
class UserSignupSerializer(serializers.ModelSerializer):
    password = serializers.CharField(write_only=True)
    confirm_password = serializers.CharField(write_only=True)

    class Meta:
        model = User
        fields = ['name','phone','email', 'password', 'confirm_password', 'role', 'referred_by']

    def validate_password(self, value):
        """Comprehensive password validation with detailed feedback"""
        from utils.validators import validate_password_strength

        errors = validate_password_strength(value)
        if errors:
            raise serializers.ValidationError(errors)
        return value

    def validate_email(self, value):
        if User.objects.filter(email=value).exists():
            raise serializers.ValidationError("An account with this email already exists. Try logging in instead.")
        return value

    def validate(self, data):
        if data.get('password') != data.get('confirm_password'):
            raise serializers.ValidationError({
                'confirm_password': ["Passwords do not match. Please ensure both password fields are identical."]
            })
        return data

    def create(self, validated_data):
        from apps.referral.models import Referral
        from apps.wallet.utils import distribute_referral_reward
        import logging

        logger = logging.getLogger(__name__)

        validated_data.pop('confirm_password')
        password = validated_data.pop('password')
        referred_by_code = validated_data.get('referred_by')

        user = User.objects.create(**validated_data)
        user.set_password(password)
        user.save()

        # Handle referral reward if user signed up with a referral code
        if referred_by_code:
            try:
                # Find the referrer by their referral code
                referrer = User.objects.get(referral_code=referred_by_code)

                # Create referral record
                referral = Referral.objects.create(
                    referrer=referrer,
                    referee=user,
                    status='pending',  # Will be set to 'credited' by distribute_referral_reward
                    referral_reward=0
                )

                # Award 100 points to referrer immediately
                distribute_referral_reward(
                    referrer_user=referrer,
                    referee_user=user,
                    referral_obj=referral
                )

                logger.info(f"Referral reward distributed: {referrer.email} referred {user.email}")

            except User.DoesNotExist:
                logger.warning(f"Invalid referral code used during signup: {referred_by_code}")
            except Exception as e:
                logger.error(f"Error processing referral reward during signup: {str(e)}")

        return user


class UserLoginSerializer(serializers.Serializer):
    email = serializers.EmailField()
    password = serializers.CharField()

    def validate(self, data):
        email = data.get('email')
        password = data.get('password')

        if not email:
            raise serializers.ValidationError({'email': ["Email address is required."]})
        if not password:
            raise serializers.ValidationError({'password': ["Password is required."]})

        # Use Django's authenticate() to enable django-axes tracking
        # Note: authenticate() expects 'username' parameter even though we're using email
        user = authenticate(
            request=self.context.get('request'),
            username=email,
            password=password
        )

        if user is None:
            # Authentication failed - either user doesn't exist or wrong password
            # Using generic message for security (prevents username enumeration)
            raise serializers.ValidationError("Invalid email or password. Please try again.")

        # Check if user account is active
        if not user.is_active:
            raise serializers.ValidationError("This account has been deactivated. Please contact support.")

        data['user'] = user
        return data


# ------------------------------
# Password Management
# ------------------------------
class ForgotPasswordSerializer(serializers.Serializer):
    email = serializers.EmailField()


class ResetPasswordSerializer(serializers.Serializer):
    """
    Serializer for password reset using email + OTP + new password.
    This replaces the old JWT-based reset with a cleaner OTP-based approach.
    """
    email = serializers.EmailField(required=True)
    otp = serializers.CharField(max_length=6, min_length=6, required=True)
    new_password = serializers.CharField(write_only=True, required=True)
    confirm_password = serializers.CharField(write_only=True, required=True)

    def validate_new_password(self, value):
        """Comprehensive password validation with detailed feedback"""
        from utils.validators import validate_password_strength

        errors = validate_password_strength(value)
        if errors:
            raise serializers.ValidationError(errors)
        return value

    def validate_otp(self, value):
        """Validate OTP format"""
        if not value.isdigit():
            raise serializers.ValidationError("OTP must contain only numbers")
        return value

    def validate(self, data):
        """Validate password confirmation match"""
        if data['new_password'] != data['confirm_password']:
            raise serializers.ValidationError({
                'confirm_password': 'Passwords do not match.'
            })
        return data


class UpdatePasswordSerializer(serializers.Serializer):
    old_password = serializers.CharField(write_only=True, required=True)
    new_password = serializers.CharField(
        write_only=True, required=True, validators=[validate_password]
    )
    new_password_confirm = serializers.CharField(write_only=True, required=True)

    def validate(self, attrs):
        if attrs["new_password"] != attrs["new_password_confirm"]:
            raise serializers.ValidationError({"new_password": "New passwords didn't match."})
        return attrs

    def validate_old_password(self, value):
        user = self.context["request"].user
        if not user.check_password(value):
            raise serializers.ValidationError("Old password is incorrect.")
        return value



# ------------------------------
# User Profile Management
# ------------------------------
class UserProfileSerializer(serializers.ModelSerializer):
    # Fetch wallet balance from related Wallet model (single source of truth)
    wallet_balance = serializers.SerializerMethodField()

    class Meta:
        model = User
        fields = ['id', 'name', 'email', 'phone', 'role', 'address_location', 'wallet_balance', 'referral_code', 'created_at']
        read_only_fields = ['id', 'referral_code', 'created_at', 'wallet_balance']

    def get_wallet_balance(self, obj):
        """Get balance from related Wallet model."""
        return str(obj.wallet.balance) if hasattr(obj, 'wallet') else "0.00"


class UserProfileUpdateSerializer(serializers.ModelSerializer):
    """Serializer for profile updates that may require OTP verification for sensitive fields"""

    class Meta:
        model = User
        fields = ['name', 'email', 'phone', 'role', 'address_location']

    def validate_email(self, value):
        """Validate email uniqueness when updating"""
        user = self.instance
        if user and user.email != value and User.objects.filter(email=value).exists():
            raise serializers.ValidationError("An account with this email already exists.")
        return value

    @staticmethod
    def requires_otp(data):
        """Check if the update contains sensitive fields that require OTP"""
        sensitive_fields = {'email', 'phone', 'role'}
        return bool(sensitive_fields.intersection(data.keys()))
