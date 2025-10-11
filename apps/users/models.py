from django.db import models
from django.contrib.auth.models import AbstractUser, BaseUserManager
import uuid
import string


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

    class Meta:
        db_table = 'users'
    ROLE_CHOICES = [
        ('disposer', 'Disposer'),
        ('recycler', 'Recycler'),
        ('admin', 'Admin'),
    ]

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    name = models.CharField(max_length=255)
    email = models.EmailField(unique=True, blank=True, null=True)
    phone = models.CharField(max_length=20, unique=True, null=True, blank=True)
    is_verified = models.BooleanField(default=False)
    role = models.CharField(max_length=20, choices=ROLE_CHOICES, default='disposer')
    address_location = models.JSONField(null=True, blank=True)
    referral_code = models.CharField(max_length=10, unique=True, blank=True)
    referred_by = models.CharField(max_length=10, null=True, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    username = None
    first_name = None
    last_name = None

    objects = UserManager()

    USERNAME_FIELD = 'email'
    REQUIRED_FIELDS = []

    def save(self, *args, **kwargs):
        if not self.referral_code:
            self.referral_code = self.generate_referral_code()
        super().save(*args, **kwargs)

    def generate_referral_code(self):
        """
        Generate a cryptographically secure unique referral code.
        Uses secrets module and checks for collisions.
        """
        import secrets
        max_attempts = 10

        for _ in range(max_attempts):
            # Use secrets for cryptographically secure random generation
            code = ''.join(secrets.choice(string.ascii_uppercase + string.digits) for _ in range(8))

            # Check for collision
            if not User.objects.filter(referral_code=code).exists():
                return code

        # Fallback: use longer code if collision persists
        return ''.join(secrets.choice(string.ascii_uppercase + string.digits) for _ in range(12))

    def get_referral_link(self, domain=None):
        """
        Generate a referral link using the user's referral code.

        Args:
            domain (str, optional): The frontend domain. If not provided, uses settings.FRONTEND_URL

        Returns:
            str: Full referral link (e.g., "https://wasteworth.com/signup?ref=ABC123DE")

        Example:
            >>> user.get_referral_link()
            'https://wasteworth.com/signup?ref=ABC123DE'

            >>> user.get_referral_link('https://app.wasteworth.com')
            'https://app.wasteworth.com/signup?ref=ABC123DE'
        """
        from django.conf import settings

        # Use provided domain or fall back to settings
        base_url = domain or getattr(settings, 'FRONTEND_URL', 'http://localhost:3000')

        # Remove trailing slash if present
        base_url = base_url.rstrip('/')

        # Construct referral link
        return f"{base_url}/signup?ref={self.referral_code}"

    def __str__(self):
        return f"{self.name} ({self.email})"
