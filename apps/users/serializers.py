from rest_framework import serializers
from django.contrib.auth.hashers import make_password
from django.core.mail import send_mail
from django.conf import settings
from django.utils import timezone
import random
import string
from .models import User, OTP


class UserSignupSerializer(serializers.ModelSerializer):
    password = serializers.CharField(write_only=True, min_length=8)
    confirm_password = serializers.CharField(write_only=True)

    class Meta:
        model = User
        fields = ['email', 'password', 'confirm_password']

    def validate(self, data):
        if data['password'] != data['confirm_password']:
            raise serializers.ValidationError("Passwords don't match")
        return data

    def validate_email(self, value):
        if User.objects.filter(email=value).exists():
            raise serializers.ValidationError("Email already exists")
        return value


    def create(self, validated_data):
        validated_data.pop('confirm_password')
        password = validated_data.pop('password')
        user = User.objects.create(**validated_data)
        user.set_password(password)
        user.save()
        return user


class UserLoginSerializer(serializers.Serializer):
    email = serializers.EmailField()
    password = serializers.CharField()

    def validate(self, data):
        email = data.get('email')
        password = data.get('password')

        if email and password:
            try:
                user = User.objects.get(email=email)
                if not user.check_password(password):
                    raise serializers.ValidationError("Invalid credentials")
                data['user'] = user
            except User.DoesNotExist:
                raise serializers.ValidationError("Invalid credentials")
        else:
            raise serializers.ValidationError("Email and password required")

        return data


# class OTPRequestSerializer(serializers.Serializer):
#     email = serializers.EmailField()

#     def validate_email(self, value):
#         try:
#             user = User.objects.get(email=value)
#             return value
#         except User.DoesNotExist:
#             raise serializers.ValidationError("No user found with this email")


# class OTPVerifySerializer(serializers.Serializer):
#     email = serializers.EmailField()
#     otp = serializers.CharField(max_length=6)

#     def validate(self, data):
#         email = data.get('email')
#         otp = data.get('otp')

#         try:
#             user = User.objects.get(email=email)
#             otp_obj = OTP.objects.filter(user=user).order_by('-created_at').first()

#             if not otp_obj:
#                 raise serializers.ValidationError("No OTP found for this user")

#             if otp_obj.is_expired():
#                 raise serializers.ValidationError("OTP has expired")

#             if not otp_obj.hashed_otp == make_password(otp, salt='otp_salt'):
#                 raise serializers.ValidationError("Invalid OTP")

#             data['user'] = user
#             data['otp_obj'] = otp_obj

#         except User.DoesNotExist:
#             raise serializers.ValidationError("No user found with this email")

#         return data


class UserProfileSerializer(serializers.ModelSerializer):
    class Meta:
        model = User
        fields = ['id', 'email', 'role', 'referral_code', 'created_at']
        read_only_fields = ['id', 'referral_code', 'created_at']