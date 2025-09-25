from django.contrib.auth.hashers import make_password
from django.utils import timezone
import random
import logging
from apps.otp.models import OTP

logger = logging.getLogger(__name__)


def generate_and_send_otp(user, purpose):
    """
    Generate OTP, save to database, and queue email sending as background task.

    Args:
        user: User instance
        purpose: OTP purpose ('signup', 'reset', 'profile_update')

    Returns:
        dict: Contains OTP instance and job information
    """
    logger.info(f"Generating OTP for user {user.email}, purpose: {purpose}")

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

    logger.info(f"OTP record created with ID: {otp_instance.id}")

    # Queue email sending as background task
    try:
        from utils.tasks import queue_otp_email

        # Determine priority based on purpose
        priority_map = {
            'reset': 'high',          # Password reset is urgent
            'profile_update': 'low',   # Profile updates are less urgent
            'signup': 'default',       # Signup is standard priority
        }
        priority = priority_map.get(purpose, 'default')

        job = queue_otp_email(user, purpose, priority)

        logger.info(f"OTP email queued successfully for {user.email}")

        return {
            'otp_instance': otp_instance,
            'job': job,
            'queued': True,
            'success': True
        }

    except Exception as e:
        logger.error(f"Failed to queue OTP email for {user.email}: {str(e)}")

        # Return OTP instance even if email queuing fails
        # This ensures the OTP exists and can be manually resent
        return {
            'otp_instance': otp_instance,
            'job': None,
            'queued': False,
            'success': False,
            'error': str(e)
        }


def generate_and_send_otp_sync(user, purpose):
    """
    Legacy synchronous OTP generation and sending.
    Use only when background tasks are not available.

    Args:
        user: User instance
        purpose: OTP purpose

    Returns:
        OTP model instance
    """
    from django.core.mail import send_mail
    from django.conf import settings

    logger.warning(f"Using synchronous OTP sending for {user.email} - consider using async version")

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

    # Send email with plain OTP (synchronous)
    subject = f'Your OTP for {purpose.title().replace("_", " ")}'
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