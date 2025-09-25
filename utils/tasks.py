"""
Background tasks for the Wasteworth application.
"""
import django_rq
from django.core.mail import send_mail
from django.conf import settings
from django.contrib.auth.hashers import make_password
from django.utils import timezone
import random
import logging

logger = logging.getLogger(__name__)


@django_rq.job('default')
def send_otp_email_async(user_id, purpose):
    """
    Background task to generate OTP, save to database, and send via email.

    Args:
        user_id: User ID (not the user object to avoid serialization issues)
        purpose: OTP purpose ('signup', 'reset', 'profile_update')

    Returns:
        dict: Result status and OTP instance ID
    """
    try:
        from django.contrib.auth import get_user_model
        from apps.otp.models import OTP

        User = get_user_model()
        user = User.objects.get(id=user_id)

        logger.info(f"Starting OTP generation for user {user.email}, purpose: {purpose}")

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

        # Send email with plain OTP
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

        logger.info(f"OTP email sent successfully to {user.email}")

        return {
            'success': True,
            'otp_id': str(otp_instance.id),
            'user_email': user.email,
            'purpose': purpose
        }

    except Exception as e:
        logger.error(f"Failed to send OTP email for user_id {user_id}, purpose {purpose}: {str(e)}")
        return {
            'success': False,
            'error': str(e),
            'user_id': user_id,
            'purpose': purpose
        }


@django_rq.job('high')  # High priority for password reset
def send_password_reset_email_async(user_id):
    """
    Background task specifically for password reset emails.
    Uses high priority queue for faster processing.
    """
    return send_otp_email_async(user_id, 'reset')


@django_rq.job('low')  # Low priority for profile updates
def send_profile_update_email_async(user_id):
    """
    Background task specifically for profile update emails.
    Uses low priority queue.
    """
    return send_otp_email_async(user_id, 'profile_update')


def queue_otp_email(user, purpose, priority='default'):
    """
    Helper function to queue OTP email tasks.

    Args:
        user: User instance
        purpose: OTP purpose
        priority: Queue priority ('default', 'high', 'low')

    Returns:
        RQ Job instance
    """
    logger.info(f"Queuing OTP email for {user.email}, purpose: {purpose}, priority: {priority}")

    queue_name = priority
    job_functions = {
        'reset': send_password_reset_email_async,
        'profile_update': send_profile_update_email_async,
        'signup': send_otp_email_async,
    }

    job_function = job_functions.get(purpose, send_otp_email_async)

    # Queue the task
    job = django_rq.enqueue(
        job_function,
        user.id,
        purpose,
        queue=queue_name
    )

    logger.info(f"OTP email task queued with job ID: {job.id}")
    return job