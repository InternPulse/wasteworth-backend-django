from rest_framework import status
from rest_framework.decorators import api_view, permission_classes
from rest_framework.permissions import AllowAny
from rest_framework.response import Response
from rest_framework.serializers import ValidationError
from rest_framework.exceptions import NotFound
from rest_framework_simplejwt.tokens import RefreshToken
from django.contrib.auth import get_user_model
from django.conf import settings
from .models import OTP
from .serializers import OTPVerifySerializer
from apps.users.serializers import UserProfileSerializer
from utils.otp import generate_and_send_otp
import logging

logger = logging.getLogger(__name__)

User = get_user_model()


@api_view(['POST'])
@permission_classes([AllowAny])
def send_otp(request):
    try:
        email_or_phone = request.data.get('email_or_phone')
        purpose = request.data.get('purpose', 'signup')

        # Find user by email or phone
        if '@' in email_or_phone:
            user = User.objects.get(email=email_or_phone)
        else:
            user = User.objects.get(phone=email_or_phone)

        # Generate and send OTP
        otp_result = generate_and_send_otp(user, purpose)

        # Check if OTP sending was successful
        if not otp_result.get('success', False):
            logger.error(f"OTP sending failed for user {email_or_phone}: {otp_result.get('error', 'Unknown error')}")
            return Response({
                'success': False,
                'error': 'Failed to send OTP. Please try again.'
            }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

        return Response({
            'success': True,
            'message': 'OTP sent successfully. If you don\'t see it in your inbox, please check your spam folder.',
            'otp_id': str(otp_result['otp_instance'].id),
            'expires_at': otp_result['otp_instance'].expires_at
        }, status=status.HTTP_200_OK)

    except User.DoesNotExist:
        raise NotFound('User not found')
    except Exception as e:
        logger.error(f"OTP sending failed for user {email_or_phone}: {str(e)}")
        return Response({
            'success': False,
            'error': 'Failed to send OTP. Please try again.'
        }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)


@api_view(['POST'])
@permission_classes([AllowAny])
def verify_otp(request):
    """Verify OTP for different actions (signup, update)"""
    action = request.query_params.get('action')

    # Validate action parameter (removed 'reset' from valid actions)
    valid_actions = ['signup', 'update']
    if not action or action not in valid_actions:
        return Response({
            'success': False,
            'error': f'Invalid or missing action. Must be one of: {", ".join(valid_actions)}'
        }, status=status.HTTP_400_BAD_REQUEST)

    # Validate OTP using serializer
    serializer = OTPVerifySerializer(data=request.data)
    if not serializer.is_valid():
        # Let the exception handler format the error properly
        raise ValidationError(serializer.errors)

    user = serializer.validated_data['user']
    otp_obj = serializer.validated_data['otp_obj']

    # Ensure OTP purpose matches the requested action
    if otp_obj.purpose != action:
        return Response({
            'success': False,
            'error': f'OTP purpose mismatch. Expected {action}, but OTP is for {otp_obj.purpose}'
        }, status=status.HTTP_400_BAD_REQUEST)

    # Mark OTP as used
    otp_obj.used = True
    otp_obj.save()

    # Handle signup action - Mark user as verified and return tokens
    if action == 'signup':
        user.is_verified = True
        user.save()

    refresh = RefreshToken.for_user(user)
    action_messages = {
        'signup': 'Account verification successful',
        'update': 'OTP verification successful'
    }

    return Response({
        'success': True,
        'message': action_messages.get(action, 'OTP verification successful'),
        'user': UserProfileSerializer(user).data,
        'tokens': {
            'refresh_token': str(refresh),
            'access': str(refresh.access_token),
        }
    }, status=status.HTTP_200_OK)


@api_view(['POST'])
@permission_classes([AllowAny])
def resend_otp(request):
    try:
        email_or_phone = request.data.get('email_or_phone')
        purpose = request.data.get('purpose', 'signup')

        # Find user
        if '@' in email_or_phone:
            user = User.objects.get(email=email_or_phone)
        else:
            user = User.objects.get(phone=email_or_phone)

        # Mark previous unused OTPs as used (security measure)
        OTP.objects.filter(user_id=user, used=False).update(used=True)

        # Generate new OTP
        otp_result = generate_and_send_otp(user, purpose)

        # Check if OTP sending was successful
        if not otp_result.get('success', False):
            logger.error(f"OTP resend failed for user {email_or_phone}: {otp_result.get('error', 'Unknown error')}")
            return Response({
                'success': False,
                'error': 'Failed to send OTP. Please try again.'
            }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

        return Response({
            'success': True,
            'message': 'New OTP sent successfully. If you don\'t see it in your inbox, please check your spam folder.',
            'otp_id': str(otp_result['otp_instance'].id)
        }, status=status.HTTP_200_OK)

    except User.DoesNotExist:
        raise NotFound('User not found')
    except Exception as e:
        logger.error(f"OTP resend failed for user {email_or_phone}: {str(e)}")
        return Response({
            'success': False,
            'error': 'Failed to send OTP. Please try again.'
        }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

