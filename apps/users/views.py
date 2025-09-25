from rest_framework import generics, status
from rest_framework.decorators import api_view, permission_classes
from rest_framework.permissions import IsAuthenticated
from rest_framework.response import Response
from rest_framework.exceptions import ValidationError, PermissionDenied
from rest_framework_simplejwt.tokens import RefreshToken
from rest_framework_simplejwt.exceptions import TokenError
from django.contrib.auth import authenticate, get_user_model
from django.conf import settings
from datetime import datetime, timedelta
import jwt
import logging

logger = logging.getLogger(__name__)

# Import error handler if it exists, otherwise create fallback
try:
    from utils.error_handler import ErrorCodes, ERROR_MESSAGES
except ImportError:
    # Fallback error handling if utils.error_handler doesn't exist
    class ErrorCodes:
        TOKEN_REQUIRED = "TOKEN_REQUIRED"
        INVALID_TOKEN = "INVALID_TOKEN"
        SERVER_ERROR = "SERVER_ERROR"
    
    ERROR_MESSAGES = {
        ErrorCodes.TOKEN_REQUIRED: "Token is required",
        ErrorCodes.INVALID_TOKEN: "Invalid token provided",
        ErrorCodes.SERVER_ERROR: "Internal server error occurred"
    }

from .models import User
from .serializers import (
    UserSignupSerializer,
    UserLoginSerializer,
    UserProfileSerializer,
    UserProfileUpdateSerializer,
    ForgotPasswordSerializer,
    ResetPasswordSerializer,
    UpdatePasswordSerializer,
)

User = get_user_model()

# ------------------------------
# User Authentication Views (Function-based)
# ------------------------------

# POST /api/v1/users/signup/
@api_view(['POST'])
def signup(request):
    serializer = UserSignupSerializer(data=request.data)
    serializer.is_valid(raise_exception=True)

    user = serializer.save()

    # Set user as unverified by default
    user.is_verified = False
    user.save()

    # Send OTP for verification (async)
    try:
        from utils.otp import generate_and_send_otp
        otp_result = generate_and_send_otp(user, 'signup')

        if otp_result['success']:
            return Response({
                'success': True,
                'message': 'Account created successfully. OTP is being sent to your email for verification.',
                'user_id': str(user.id),
                'email': user.email,
                'is_verified': user.is_verified,
                'otp_sent': otp_result['queued'],
                'otp_id': str(otp_result['otp_instance'].id),
                'next_step': 'Verify OTP using POST /api/v1/otp/verify/?action=signup to get access tokens'
            }, status=status.HTTP_201_CREATED)
        else:
            logger.error(f"OTP queuing failed for user {user.email}: {otp_result.get('error')}")
            return Response({
                'success': True,
                'message': 'Account created successfully. OTP email will be sent shortly.',
                'user_id': str(user.id),
                'email': user.email,
                'is_verified': user.is_verified,
                'otp_sent': False,
                'otp_id': str(otp_result['otp_instance'].id),
                'warning': 'OTP email may be delayed. Use POST /api/v1/otp/send/ to request another OTP if needed.'
            }, status=status.HTTP_201_CREATED)

    except Exception as e:
        logger.error(f"OTP generation failed for user {user.email}: {str(e)}")
        return Response({
            'success': True,
            'message': 'Account created successfully, but failed to generate verification OTP.',
            'user_id': str(user.id),
            'email': user.email,
            'is_verified': user.is_verified,
            'otp_sent': False,
            'error': 'Failed to generate OTP. Use POST /api/v1/otp/send/ to request verification OTP.'
        }, status=status.HTTP_201_CREATED)


# POST /api/v1/users/login/
@api_view(['POST'])
def login(request):
    serializer = UserLoginSerializer(data=request.data)
    serializer.is_valid(raise_exception=True)

    user = serializer.validated_data['user']
    refresh = RefreshToken.for_user(user)
    return Response({
        'success': True,
        'message': 'Login successful',
        'user': UserProfileSerializer(user).data,
        'tokens': {
            'refresh_token': str(refresh),
            'access': str(refresh.access_token),
        }
    }, status=status.HTTP_200_OK)


# POST /api/v1/users/logout/
@api_view(['POST'])
def logout(request):
    try:
        refresh_token = request.data.get('refresh_token')
        if not refresh_token:
            return Response({
                'success': False,
                'error': {
                    'code': ErrorCodes.TOKEN_REQUIRED,
                    'message': ERROR_MESSAGES[ErrorCodes.TOKEN_REQUIRED],
                    'details': {'refresh_token': ['Refresh token is required to log out securely.']}
                }
            }, status=status.HTTP_401_UNAUTHORIZED)

        token = RefreshToken(refresh_token)
        token.blacklist()
        return Response({
            'success': True,
            'message': 'Logout successful'
        }, status=status.HTTP_200_OK)

    except TokenError:
        return Response({
            'success': False,
            'error': {
                'code': ErrorCodes.INVALID_TOKEN,
                'message': ERROR_MESSAGES[ErrorCodes.INVALID_TOKEN],
                'details': {'refresh_token': ['The provided refresh token is invalid or expired.']}
            }
        }, status=status.HTTP_401_UNAUTHORIZED)
    except Exception as e:
        logger.error(f"Token refresh failed: {str(e)}")
        return Response({
            'success': False,
            'error': {
                'code': ErrorCodes.SERVER_ERROR,
                'message': ERROR_MESSAGES[ErrorCodes.SERVER_ERROR],
                'details': {'error': ['An unexpected error occurred during logout.']}
            }
        }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)


# ------------------------------
# Password Management Views (Class-based)
# ------------------------------

# POST /api/v1/users/forgotPassword/
class ForgotPasswordView(generics.GenericAPIView):
    serializer_class = ForgotPasswordSerializer
    permission_classes = []  # No auth needed

    def post(self, request, *args, **kwargs):
        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)

        email = serializer.validated_data["email"]
        user = User.objects.filter(email=email).first()

        # Always return generic message for security
        if not user:
            return Response({
                "success": True,
                "message": "If the email exists, password reset instructions will be sent."
            }, status=status.HTTP_200_OK)

        # Send OTP for password reset (async)
        try:
            from utils.otp import generate_and_send_otp
            otp_result = generate_and_send_otp(user, 'reset')

            # Always return success for security (don't reveal if email exists)
            return Response({
                "success": True,
                "message": "If the email exists, password reset instructions will be sent.",
                "next_step": "Use POST /api/v1/otp/verify/?action=reset with email, otp, and new_password"
            }, status=status.HTTP_200_OK)

        except Exception as e:
            logger.error(f"Password reset OTP generation failed for user {user.email}: {str(e)}")
            return Response({
                "success": True,  # Still return success for security
                "message": "If the email exists, password reset instructions will be sent."
            }, status=status.HTTP_200_OK)


# PATCH /api/v1/users/updatePassword/
class UpdatePasswordView(generics.GenericAPIView):
    serializer_class = UpdatePasswordSerializer
    permission_classes = [IsAuthenticated]

    def patch(self, request, *args, **kwargs):
        # Check if OTP is provided in the request
        otp_code = request.data.get('otp')

        if not otp_code:
            # Step 1: Send OTP first
            old_password = request.data.get('old_password')

            if not old_password:
                raise ValidationError('old_password is required to send OTP')

            user = request.user

            # Verify current password
            if not user.check_password(old_password):
                raise ValidationError('Current password is incorrect')

            # Send OTP (async)
            try:
                from utils.otp import generate_and_send_otp
                otp_result = generate_and_send_otp(user, 'reset')

                if otp_result['success']:
                    return Response({
                        'success': True,
                        'message': 'OTP is being sent to your email. Please provide OTP and new_password to complete password update.',
                        'otp_id': str(otp_result['otp_instance'].id),
                        'otp_queued': otp_result['queued']
                    }, status=status.HTTP_200_OK)
                else:
                    return Response({
                        'success': True,
                        'message': 'OTP will be sent to your email shortly. Please provide OTP and new_password to complete password update.',
                        'otp_id': str(otp_result['otp_instance'].id),
                        'otp_queued': False
                    }, status=status.HTTP_200_OK)
            except Exception as e:
                logger.error(f"Password update OTP generation failed for user {user.email}: {str(e)}")
                raise ValidationError('Failed to generate OTP. Please try again.')

        else:
            # Step 2: Verify OTP and update password
            from apps.otp.serializers import OTPVerifySerializer

            user = request.user
            verify_data = {
                'user_id': str(user.id),
                'otp': otp_code
            }

            # Verify OTP
            otp_serializer = OTPVerifySerializer(data=verify_data)
            otp_serializer.is_valid(raise_exception=True)

            otp_user = otp_serializer.validated_data['user']
            otp_obj = otp_serializer.validated_data['otp_obj']

            # Ensure OTP is for password reset and belongs to authenticated user
            if otp_obj.purpose != 'reset':
                raise ValidationError('OTP is not for password reset')

            if otp_user.id != user.id:
                raise PermissionDenied('OTP does not belong to authenticated user')

            # Validate new password using serializer
            serializer = self.get_serializer(data=request.data)
            serializer.is_valid(raise_exception=True)

            # Mark OTP as used
            otp_obj.used = True
            otp_obj.save()

            # Update password
            user.set_password(serializer.validated_data["new_password"])
            user.save()

            return Response({
                'success': True,
                'message': 'Password updated successfully'
            }, status=status.HTTP_200_OK)

# ------------------------------
# User Profile Management Views (Class-based)
# ------------------------------

# GET /api/v1/users/user-dashboard/
class UserDashboardView(generics.GenericAPIView):
    permission_classes = [IsAuthenticated]

    def get(self, request):
        serializer = UserProfileSerializer(request.user)
        return Response(serializer.data, status=status.HTTP_200_OK)


# PATCH /api/v1/users/update-user/
class UpdateUserView(generics.GenericAPIView):
    serializer_class = UserProfileUpdateSerializer
    permission_classes = [IsAuthenticated]

    def patch(self, request):
        user = request.user
        otp_code = request.data.get('otp')

        if not otp_code:
            # Step 1: Check if OTP is required for this update
            if UserProfileUpdateSerializer.requires_otp(request.data):
                # Validate the data first
                serializer = self.get_serializer(user, data=request.data, partial=True)
                serializer.is_valid(raise_exception=True)

                # Send OTP for profile update (async)
                try:
                    from utils.otp import generate_and_send_otp
                    otp_result = generate_and_send_otp(user, 'profile_update')

                    if otp_result['success']:
                        return Response({
                            'success': True,
                            'message': 'Profile update requires verification. OTP is being sent to your email.',
                            'otp_id': str(otp_result['otp_instance'].id),
                            'otp_queued': otp_result['queued'],
                            'next_step': 'Provide the same data along with the OTP to complete the update'
                        }, status=status.HTTP_200_OK)
                    else:
                        return Response({
                            'success': True,
                            'message': 'Profile update requires verification. OTP will be sent to your email shortly.',
                            'otp_id': str(otp_result['otp_instance'].id),
                            'otp_queued': False,
                            'next_step': 'Provide the same data along with the OTP to complete the update'
                        }, status=status.HTTP_200_OK)
                except Exception as e:
                    logger.error(f"Profile update OTP generation failed for user {user.email}: {str(e)}")
                    return Response({
                        'success': False,
                        'error': 'Failed to generate OTP. Please try again.'
                    }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
            else:
                # Direct update for non-sensitive fields
                serializer = self.get_serializer(user, data=request.data, partial=True)
                serializer.is_valid(raise_exception=True)
                serializer.save()
                return Response({
                    'success': True,
                    'message': 'Profile updated successfully',
                    'data': UserProfileSerializer(user).data
                }, status=status.HTTP_200_OK)
        else:
            # Step 2: Verify OTP and update profile
            from apps.otp.serializers import OTPVerifySerializer

            verify_data = {
                'user_id': str(user.id),
                'otp': otp_code
            }

            # Verify OTP
            otp_serializer = OTPVerifySerializer(data=verify_data)
            otp_serializer.is_valid(raise_exception=True)

            otp_user = otp_serializer.validated_data['user']
            otp_obj = otp_serializer.validated_data['otp_obj']

            # Ensure OTP is for profile update and belongs to authenticated user
            if otp_obj.purpose != 'profile_update':
                raise ValidationError('OTP is not for profile update')

            if otp_user.id != user.id:
                raise PermissionDenied('OTP does not belong to authenticated user')

            # Validate and apply profile changes
            serializer = self.get_serializer(user, data=request.data, partial=True)
            serializer.is_valid(raise_exception=True)

            # Mark OTP as used
            otp_obj.used = True
            otp_obj.save()

            # Apply profile update
            serializer.save()

            return Response({
                'success': True,
                'message': 'Profile updated successfully',
                'data': UserProfileSerializer(user).data
            }, status=status.HTTP_200_OK)
