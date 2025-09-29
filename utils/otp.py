from django.contrib.auth.hashers import make_password
from django.utils import timezone
import random
import logging
from apps.otp.models import OTP

logger = logging.getLogger(__name__)


# OLD Redis/Queue Implementation (commented out)
# def generate_and_send_otp_old(user, purpose):
#     """OLD: Generate OTP, save to database, and queue email sending as background task."""
#     # ... old implementation commented out

def generate_and_send_otp(user, purpose):
    """
    Generate OTP, save to database, and send email directly using Resend.

    Args:
        user: User instance
        purpose: OTP purpose ('signup', 'reset', 'profile_update')

    Returns:
        dict: Contains OTP instance and sending status
    """
    from django.core.mail import send_mail
    from django.conf import settings

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

    # Send email directly (Resend handles async delivery)
    try:
        subject = f'Your OTP for {purpose.title().replace("_", " ")}'
        message = f'Your OTP code is: {otp_code}\n\nThis code will expire in 10 minutes.'
        from_email = getattr(settings, 'DEFAULT_FROM_EMAIL', 'no-reply@wasteworth.com')

        send_mail(
            subject=subject,
            message=message,
            from_email=from_email,
            recipient_list=[user.email],
            fail_silently=False,
        )

        logger.info(f"OTP email sent successfully to {user.email}")

        return {
            'otp_instance': otp_instance,
            'job': None,  # No job needed with direct sending
            'queued': True,  # Keep for backward compatibility
            'success': True
        }

    except Exception as e:
        logger.error(f"Failed to send OTP email to {user.email}: {str(e)}")
        import traceback
        logger.error(f"Full traceback: {traceback.format_exc()}")

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