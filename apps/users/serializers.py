from rest_framework import serializers
from django.contrib.auth.hashers import make_password, check_password
from django.core.mail import send_mail
from django.conf import settings
from django.utils import timezone
import random
import string
from .models import User, OTP


class UserSignupSerializer(serializers.ModelSerializer):
    password = serializers.CharField(write_only=True, min_length=8)
    confirmPassword = serializers.CharField(write_only=True, source='confirm_password')
    referralCode = serializers.CharField(required=False, allow_blank=True, source='referral_code')
    addressLocation = serializers.CharField(required=False, allow_blank=True, source='address_location')  # Added field

    class Meta:
        model = User
        fields = ['name', 'email', 'phone', 'password', 'confirmPassword', 'role', 'referralCode', 'addressLocation']  # Added addressLocation

    def validate(self, data):
        if data['password'] != data.get('confirm_password'):
            raise serializers.ValidationError({"confirmPassword": "Passwords don't match"})
        return data

    def validate_email(self, value):
        if User.objects.filter(email=value).exists():
            raise serializers.ValidationError("Email already exists")
        return value

    def validate_referralCode(self, value):
        if value and not User.objects.filter(referral_code=value).exists():
            raise serializers.ValidationError("Invalid referral code")
        return value

    def create(self, validated_data):
        validated_data.pop('confirm_password', None)
        password = validated_data.pop('password')
        referral_code = validated_data.pop('referral_code', None)
        
        # Set referred_by if referral code is provided
        if referral_code:
            validated_data['referred_by'] = referral_code
            
        user = User.objects.create(**validated_data)
        user.set_password(password)
        user.save()
        return user


class UserLoginSerializer(serializers.Serializer):
    emailOrPhone = serializers.CharField()
    password = serializers.CharField()

    def validate(self, data):
        email_or_phone = data.get('emailOrPhone')
        password = data.get('password')

        if email_or_phone and password:
            try:
                # Detect if input is email or phone
                if '@' in email_or_phone:
                    user = User.objects.get(email=email_or_phone)
                else:
                    user = User.objects.get(phone=email_or_phone)
                    
                if not user.check_password(password):
                    raise serializers.ValidationError({"password": "Invalid credentials"})
                data['user'] = user
            except User.DoesNotExist:
                raise serializers.ValidationError({"emailOrPhone": "Invalid credentials"})
        else:
            if not email_or_phone:
                raise serializers.ValidationError({"emailOrPhone": "Email or phone required"})
            if not password:
                raise serializers.ValidationError({"password": "Password required"})

        return data


class OTPVerifySerializer(serializers.Serializer):
    userId = serializers.UUIDField(required=False)
    emailOrPhone = serializers.CharField(required=False)
    otp = serializers.CharField(max_length=6)

    def validate(self, data):
        user_id = data.get('userId')
        email_or_phone = data.get('emailOrPhone')
        otp = data.get('otp')

        if not user_id and not email_or_phone:
            raise serializers.ValidationError({"userId": "Either userId or emailOrPhone is required"})

        try:
            # Try to find user by userId first, then by emailOrPhone
            if user_id:
                user = User.objects.get(id=user_id)
            else:
                if '@' in email_or_phone:
                    user = User.objects.get(email=email_or_phone)
                else:
                    user = User.objects.get(phone=email_or_phone)

            # Get the most recent unused OTP
            otp_obj = OTP.objects.filter(
                user=user, 
                used=False
            ).order_by('-created_at').first()

            if not otp_obj:
                raise serializers.ValidationError({"otp": "No valid OTP found for this user"})

            if otp_obj.is_expired():
                raise serializers.ValidationError({"otp": "OTP has expired"})

            # Check OTP using check_password
            if not check_password(otp, otp_obj.hashed_otp):
                raise serializers.ValidationError({"otp": "Invalid OTP"})

            data['user'] = user
            data['otp_obj'] = otp_obj

        except User.DoesNotExist:
            if user_id:
                raise serializers.ValidationError({"userId": "No user found with this ID"})
            else:
                raise serializers.ValidationError({"emailOrPhone": "No user found with this email or phone"})

        return data


class UserProfileSerializer(serializers.ModelSerializer):
    userId = serializers.UUIDField(source='id', read_only=True)
    isVerified = serializers.BooleanField(source='is_verified', read_only=True)
    walletBalance = serializers.DecimalField(source='wallet_balance', max_digits=10, decimal_places=2, read_only=True)
    referralCode = serializers.CharField(source='referral_code', read_only=True)
    referredBy = serializers.CharField(source='referred_by', read_only=True)
    createdAt = serializers.DateTimeField(source='created_at', read_only=True)
    updatedAt = serializers.DateTimeField(source='updated_at', read_only=True)
    addressLocation = serializers.CharField(source='address_location', read_only=True)  # Added field
    location = serializers.SerializerMethodField()

    class Meta:
        model = User
        fields = [
            'userId', 'name', 'email', 'phone', 'role', 'isVerified', 'location', 'addressLocation',  # Added isVerified
            'walletBalance', 'referralCode', 'referredBy', 'createdAt', 'updatedAt'
        ]

    def get_location(self, obj):
        if obj.location_lat is not None and obj.location_lng is not None:
            return {
                'lat': obj.location_lat,
                'lng': obj.location_lng
            }
        return None


class OTPSerializer(serializers.ModelSerializer):
    """
    OTP serializer for internal/admin/test uses.
    Exposes safe fields in camelCase format.
    Does NOT expose hashed_otp or other secrets.
    """
    otpId = serializers.UUIDField(source='id', read_only=True)
    userId = serializers.UUIDField(source='user.id', read_only=True)
    expiresAt = serializers.DateTimeField(source='expires_at', read_only=True)
    createdAt = serializers.DateTimeField(source='created_at', read_only=True)
    isExpired = serializers.SerializerMethodField()
    isUsed = serializers.BooleanField(source='used', read_only=True)

    class Meta:
        model = OTP
        fields = [
            'otpId', 'userId', 'purpose', 'isUsed', 'isExpired', 
            'expiresAt', 'createdAt'
        ]
        # Explicitly exclude sensitive fields from serialization
        extra_kwargs = {
            'hashed_otp': {'write_only': True},
        }

    def get_isExpired(self, obj):
        """Check if OTP is expired"""
        return obj.is_expired()