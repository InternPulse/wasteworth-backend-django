from rest_framework import serializers
from django.contrib.auth.hashers import make_password
from django.core.mail import send_mail
from django.conf import settings
from django.utils import timezone
import random
import string
import re
from .models import User, OTP


class UserSignupSerializer(serializers.ModelSerializer):
    password = serializers.CharField(write_only=True)
    confirm_password = serializers.CharField(write_only=True)

    class Meta:
        model = User
        fields = ['name', 'email', 'password', 'confirm_password', 'role']

    def validate_password(self, value):
        """Comprehensive password validation with detailed feedback"""
        errors = []

        # Length check
        if len(value) < 8:
            errors.append("Password must be at least 8 characters long")

        # Character requirements
        if not re.search(r'[A-Z]', value):
            errors.append("Password must contain at least one uppercase letter")
        if not re.search(r'[a-z]', value):
            errors.append("Password must contain at least one lowercase letter")
        if not re.search(r'\d', value):
            errors.append("Password must contain at least one number")
        if not re.search(r'[!@#$%^&*(),.?":{}|<>]', value):
            errors.append("Password must contain at least one special character")

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

        if not email:
            raise serializers.ValidationError({'email': ["Email address is required."]})
        if not password:
            raise serializers.ValidationError({'password': ["Password is required."]})

        try:
            user = User.objects.get(email=email)
            if not user.check_password(password):
                raise serializers.ValidationError("The password you entered is incorrect. Please try again.")
            data['user'] = user
        except User.DoesNotExist:
            raise serializers.ValidationError("No account found with this email address. Please check your email or sign up.")

        return data



class UserProfileSerializer(serializers.ModelSerializer):
    class Meta:
        model = User
        fields = ['id', 'name', 'email', 'phone', 'role', 'location_lat', 'location_lng', 'address_location', 'wallet_balance', 'referral_code', 'created_at']
        read_only_fields = ['id', 'referral_code', 'created_at', 'wallet_balance']