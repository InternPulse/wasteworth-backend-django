from django.core.mail import send_mail
from django.conf import settings
from django.contrib.auth.hashers import make_password
from django.utils import timezone
import random
from apps.otp.models import OTP


def generate_and_send_otp(user, purpose):
    """
    Generate a 6-digit OTP, hash it, save to database, and send via email.
    
    Args:
        user: User instance
        purpose: OTP purpose ('signup', 'password change', 'password reset')
    
    Returns:
        OTP model instance
    """
    # Generate 6-digit zero-padded numeric OTP
    otp_code = f"{random.randint(0, 999999):06d}"
    
    # Hash the OTP before storing
    hashed_otp = make_password(otp_code)
    
    # Create OTP record
    otp_instance = OTP.objects.create(
        user_id=user,
        hashed_otp=hashed_otp,
        purpose=purpose,
        used=False,
        expires_at=timezone.now() + timezone.timedelta(minutes=10)
    )
    
    # Send email with plain OTP
    subject = f'Your OTP for {purpose.title()}'
    message = f'Your OTP code is: {otp_code}\n\nThis code will expire in 10 minutes.'
    from_email = getattr(settings, 'DEFAULT_FROM_EMAIL', 'noreply@wasteworth.com')
    
    send_mail(
        subject=subject,
        message=message,
        from_email=from_email,
        recipient_list=[user.email],
        fail_silently=False,
    )
    
    return otp_instance