from rest_framework import serializers
from django.contrib.auth import get_user_model
from django.contrib.auth.hashers import check_password
from .models import OTP

User = get_user_model()


class OTPSerializer(serializers.ModelSerializer):
    """
    OTP serializer for internal/admin/test uses.
    Exposes safe fields in camelCase format.
    Does NOT expose hashed_otp or other secrets.
    """
    otp_id = serializers.UUIDField(source='id', read_only=True)
    user_id = serializers.UUIDField(source='user_id.id', read_only=True)
    expires_at = serializers.DateTimeField(source='expires_at', read_only=True)
    created_at = serializers.DateTimeField(source='created_at', read_only=True)
    is_expired = serializers.SerializerMethodField()
    is_used = serializers.BooleanField(source='used', read_only=True)

    class Meta:
        model = OTP
        fields = [
            'otp_id', 'user_id', 'purpose', 'is_used', 'is_expired',
            'expires_at', 'created_at'
        ]
        # Explicitly exclude sensitive fields from serialization
        extra_kwargs = {
            'hashed_otp': {'write_only': True},
        }

    def get_is_expired(self, obj):
        """Check if OTP is expired"""
        return obj.is_expired()


class OTPVerifySerializer(serializers.Serializer):
    user_id = serializers.UUIDField(required=False)
    email_or_phone = serializers.CharField(required=False)
    otp = serializers.CharField(max_length=6)

    def validate(self, data):
        user_id = data.get('user_id')
        email_or_phone = data.get('email_or_phone')
        otp = data.get('otp')

        if not user_id and not email_or_phone:
            raise serializers.ValidationError({"user_id": "Either user_id or email_or_phone is required"})

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
                user_id=user,
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
                raise serializers.ValidationError({"user_id": "No user found with this ID"})
            else:
                raise serializers.ValidationError({"email_or_phone": "No user found with this email or phone"})

        return data


class OTPRequestSerializer(serializers.Serializer):
    """Serializer for requesting an OTP"""
    user_id = serializers.UUIDField(required=False)
    email_or_phone = serializers.CharField(required=False)
    purpose = serializers.ChoiceField(choices=OTP.PURPOSE_CHOICES, default='signup')

    def validate(self, data):
        user_id = data.get('user_id')
        email_or_phone = data.get('email_or_phone')

        if not user_id and not email_or_phone:
            raise serializers.ValidationError({"user_id": "Either user_id or email_or_phone is required"})

        try:
            # Try to find user by userId first, then by emailOrPhone
            if user_id:
                user = User.objects.get(id=user_id)
            else:
                if '@' in email_or_phone:
                    user = User.objects.get(email=email_or_phone)
                else:
                    user = User.objects.get(phone=email_or_phone)

            data['user'] = user

        except User.DoesNotExist:
            if user_id:
                raise serializers.ValidationError({"user_id": "No user found with this ID"})
            else:
                raise serializers.ValidationError({"email_or_phone": "No user found with this email or phone"})

        return data