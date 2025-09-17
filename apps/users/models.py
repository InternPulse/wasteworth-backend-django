from django.contrib.auth.models import AbstractUser, BaseUserManager
from django.db import models
from django.contrib.auth.hashers import make_password
from django.utils import timezone
import uuid
import string
import random


class UserManager(BaseUserManager):
    def create_user(self, email, password=None, **extra_fields):
        if not email:
            raise ValueError('The Email field must be set')

        email = self.normalize_email(email)
        user = self.model(email=email, **extra_fields)
        user.set_password(password)
        user.save(using=self._db)
        return user

    def create_superuser(self, email, password=None, **extra_fields):
        extra_fields.setdefault('is_staff', True)
        extra_fields.setdefault('is_superuser', True)
        extra_fields.setdefault('role', 'admin')

        if extra_fields.get('is_staff') is not True:
            raise ValueError('Superuser must have is_staff=True.')
        if extra_fields.get('is_superuser') is not True:
            raise ValueError('Superuser must have is_superuser=True.')

        return self.create_user(email, password, **extra_fields)


class User(AbstractUser):
    ROLE_CHOICES = [
        ('disposer', 'Disposer'),
        ('recycler', 'Recycler'),
        ('admin', 'Admin'),
    ]

    userId = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    name = models.CharField(max_length=255, null=True, blank=True)
    email = models.EmailField(unique=True)
    phone = models.CharField(max_length=20, unique=True, null=True, blank=True)
    role = models.CharField(max_length=20, choices=ROLE_CHOICES, default='disposer')
    location = models.JSONField(null=True, blank=True)  # { "lat": float, "lng": float }
    walletBalance = models.DecimalField(max_digits=10, decimal_places=2, default=0.00)
    referralCode = models.CharField(max_length=10, unique=True, blank=True)
    referredBy = models.CharField(max_length=10, null=True, blank=True)
    createdAt = models.DateTimeField(auto_now_add=True)
    updatedAt = models.DateTimeField(auto_now=True)

    username = None
    first_name = None
    last_name = None

    objects = UserManager()

    USERNAME_FIELD = 'email'
    REQUIRED_FIELDS = []

    def save(self, *args, **kwargs):
        if not self.referralCode:
            self.referralCode = self.generate_referral_code()
        super().save(*args, **kwargs)

    def generate_referral_code(self):
        return ''.join(random.choices(string.ascii_uppercase + string.digits, k=8))

    def __str__(self):
        return f"{self.name} ({self.email})"


class OTP(models.Model):
    otpId = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    userId = models.ForeignKey(User, on_delete=models.CASCADE, related_name='otps')
    hashedOtp = models.CharField(max_length=255)
    expiresAt = models.DateTimeField()
    createdAt = models.DateTimeField(auto_now_add=True)

    def save(self, *args, **kwargs):
        if not self.expiresAt:
            self.expiresAt = timezone.now() + timezone.timedelta(minutes=10)
        super().save(*args, **kwargs)

    def is_expired(self):
        return timezone.now() > self.expiresAt

    def __str__(self):
        return f"OTP for {self.userId.name} - {'Expired' if self.is_expired() else 'Valid'}"
