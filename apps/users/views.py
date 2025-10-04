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
import requests
from utils.rate_limiter import rate_limit, ip_key, user_key

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

# POST /api/v1/users/signup/ - Create user account (OTP sending is separate)
@rate_limit(key_func=ip_key('signup'), rate=10, per=86400)  # 10 signups per day per IP
@api_view(['POST'])
def signup(request):
    serializer = UserSignupSerializer(data=request.data)
    serializer.is_valid(raise_exception=True)

    user = serializer.save()

    # Set user as unverified by default
    user.is_verified = False
    user.save()

    return Response({
        'success': True,
        'message': 'Account created successfully. Use POST /api/v1/otp/send/ to request verification OTP.',
        'user_id': str(user.id),
        'email': user.email,
        'is_verified': user.is_verified,
        'next_step': 'Send OTP using POST /api/v1/otp/send/ then verify with POST /api/v1/otp/verify/?action=signup'
    }, status=status.HTTP_201_CREATED)


# POST /api/v1/users/login/
@rate_limit(key_func=ip_key('login'), rate=10, per=600)  # 10 attempts per 10 minutes per IP
@api_view(['POST'])
def login(request):
    # Pass request context to serializer so authenticate() can access it for axes tracking
    serializer = UserLoginSerializer(data=request.data, context={'request': request})
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
@rate_limit(key_func=user_key('logout'), rate=20, per=60)  # 20 requests per minute per user
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

    @rate_limit(key_func=ip_key('forgot_password'), rate=3, per=3600)  # 3 requests per hour per IP
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

            # Check if OTP sending failed, but still return success for security
            if not otp_result.get('success', False):
                logger.error(f"Password reset OTP generation failed for user {user.email}: {otp_result.get('error', 'Unknown error')}")

            # Always return success for security (don't reveal if email exists)
            return Response({
                "success": True,
                "message": "If the email exists, password reset instructions will be sent.",
                "next_step": "Use POST /api/v1/users/resetPassword/ with email, otp, new_password, and confirm_password"
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

    @rate_limit(key_func=user_key('update_password'), rate=5, per=3600)  # 5 attempts per hour per user
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
    """
    User dashboard endpoint that combines user profile data with listing statistics
    from the Node.js service.
    """
    permission_classes = [IsAuthenticated]

    def _fetch_listing_data(self, user_id, auth_token=None):
        """
        Fetch listing summary from Node.js service.

        Args:
            user_id: The user ID to fetch listings for
            auth_token: JWT token from the authenticated user (optional)

        Returns:
            tuple: (dict with 'total_listings' and 'sold_listings', node_status string)
                   Returns default values (0, 0) and 'unavailable' if Node service fails
        """
        default_data = {
            'total_listings': 0,
            'sold_listings': 0
        }

        # Check if Node service is configured
        if not settings.NODE_SERVICE_URL or not settings.INTERNAL_API_KEY:
            logger.warning(
                "Node service not configured. Set NODE_SERVICE_URL and INTERNAL_API_KEY in environment.",
                extra={'node_status': 'unavailable'}
            )
            return default_data, 'unavailable'

        # Check if auth token is provided
        if not auth_token:
            logger.warning(
                "No authentication token provided for Node service request",
                extra={'node_status': 'unavailable', 'user_id': str(user_id)}
            )
            return default_data, 'unavailable'

        try:
            # Build the URL
            url = f"{settings.NODE_SERVICE_URL}/api/v1/listings/listingstats"

            # Make request with timeout
            # Note: headers built inline to avoid storing sensitive data in variables
            response = requests.get(
                url,
                headers={
                    'Authorization': f'Bearer {auth_token}',
                    'api_key': f'Bearer {settings.INTERNAL_API_KEY}',
                    'Content-Type': 'application/json'
                },
                timeout=10  # 10 second timeout
            )

            # Raise exception for 4xx/5xx status codes
            response.raise_for_status()

            # Parse JSON response
            data = response.json()

            # Extract listing data with fallback to defaults
            # Node returns: total_waste_posted, total_waste_completed
            # We map them to: total_listings, sold_listings
            listing_data = {
                'total_listings': data.get('total_waste_posted', data.get('total_listings', 0)),
                'sold_listings': data.get('total_waste_completed', data.get('sold_listings', 0))
            }

            # Log success
            logger.info(
                f"Successfully fetched listing data for user {user_id}",
                extra={'node_status': 'ok', 'user_id': str(user_id)}
            )

            return listing_data, 'ok'

        except requests.exceptions.Timeout:
            logger.error(
                f"Timeout fetching listing data for user {user_id} from Node service",
                extra={'node_status': 'unavailable', 'user_id': str(user_id)}
            )
            return default_data, 'unavailable'

        except requests.exceptions.ConnectionError:
            logger.error(
                f"Connection error fetching listing data for user {user_id} from Node service",
                extra={'node_status': 'unavailable', 'user_id': str(user_id)}
            )
            return default_data, 'unavailable'

        except requests.exceptions.HTTPError as e:
            status_code = e.response.status_code if e.response else 'unknown'
            logger.error(
                f"HTTP error fetching listing data for user {user_id}: {status_code}",
                extra={'node_status': 'unavailable', 'user_id': str(user_id)}
            )
            return default_data, 'unavailable'

        except (ValueError, KeyError):
            logger.error(
                f"Invalid JSON response from Node service for user {user_id}",
                extra={'node_status': 'unavailable', 'user_id': str(user_id)}
            )
            return default_data, 'unavailable'

        except Exception:
            # Don't log exception details as they may contain sensitive headers
            logger.error(
                f"Unexpected error fetching listing data for user {user_id}",
                extra={'node_status': 'unavailable', 'user_id': str(user_id)}
            )
            return default_data, 'unavailable'

    @rate_limit(key_func=user_key('dashboard'),rate=30,per=60)
    def get(self, request):
        """
        Get user dashboard data including profile and listing statistics.

        Returns user profile data merged with listing data from Node.js service.
        If Node service fails, returns user profile with default listing values (0).

        Logs node_status internally ('ok' or 'unavailable') for monitoring.
        """
        # Serialize user profile data
        serializer = UserProfileSerializer(request.user)
        user_data = serializer.data

        # Extract JWT token from Authorization header
        auth_header = request.META.get('HTTP_AUTHORIZATION', '')
        auth_token = None
        if auth_header.startswith('Bearer '):
            auth_token = auth_header.split(' ')[1]

        # Fetch listing data from Node service with user's JWT token
        listing_data, node_status = self._fetch_listing_data(request.user.id, auth_token)

        # Log the node status (internal monitoring only, not exposed to frontend)
        logger.info(
            f"Dashboard request for user {request.user.id}",
            extra={
                'user_id': str(request.user.id),
                'node_status': node_status,
                'endpoint': 'user_dashboard'
            }
        )

        # Merge user data with listing data (node_status NOT included)
        dashboard_data = {
            **user_data,
            **listing_data
        }

        return Response(dashboard_data, status=status.HTTP_200_OK)


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


# POST /api/v1/users/resetPassword/
class ResetPasswordView(generics.GenericAPIView):
    """
    Reset user password using email + OTP + new password.
    This is a clean, one-step password reset that replaces the old JWT-based approach.
    """
    serializer_class = ResetPasswordSerializer
    permission_classes = []  # No authentication required

    @rate_limit(key_func=ip_key('reset_password'), rate=5, per=3600)  # 5 attempts per hour per IP
    def post(self, request):
        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)

        email = serializer.validated_data['email']
        otp_code = serializer.validated_data['otp']
        new_password = serializer.validated_data['new_password']

        try:
            # 1. Find user by email
            user = User.objects.get(email=email)

            # 2. Verify OTP internally
            from apps.otp.models import OTP
            from django.utils import timezone
            from django.contrib.auth.hashers import check_password

            otp_obj = OTP.objects.filter(
                user_id=user,
                purpose='reset',
                used=False,
                expires_at__gt=timezone.now()
            ).first()

            if not otp_obj or not check_password(otp_code, otp_obj.hashed_otp):
                return Response({
                    'success': False,
                    'error': {
                        'code': 'INVALID_OTP',
                        'message': 'The OTP provided is invalid or has expired.',
                        'details': {'otp': ['Invalid or expired OTP code.']}
                    }
                }, status=status.HTTP_400_BAD_REQUEST)

            # 3. Reset password
            user.set_password(new_password)
            user.save()

            # 4. Mark OTP as used
            otp_obj.used = True
            otp_obj.save()

            # 5. Invalidate all existing tokens for security
            try:
                from rest_framework_simplejwt.token_blacklist.models import OutstandingToken
                tokens = OutstandingToken.objects.filter(user=user)
                for token in tokens:
                    token.blacklist()
            except Exception as e:
                # Token blacklisting is not critical, just log the error
                logger.warning(f"Failed to blacklist tokens for user {user.email}: {str(e)}")

            logger.info(f"Password reset successful for user {user.email}")
            return Response({
                'success': True,
                'message': 'Password reset successful. Please login with your new password.'
            }, status=status.HTTP_200_OK)

        except User.DoesNotExist:
            return Response({
                'success': False,
                'error': {
                    'code': 'USER_NOT_FOUND',
                    'message': 'No account found with the provided email address.',
                    'details': {'email': ['User with this email does not exist.']}
                }
            }, status=status.HTTP_404_NOT_FOUND)
        except Exception as e:
            logger.error(f"Password reset failed for {email}: {str(e)}")
            return Response({
                'success': False,
                'error': {
                    'code': ErrorCodes.SERVER_ERROR,
                    'message': ERROR_MESSAGES[ErrorCodes.SERVER_ERROR],
                    'details': {'error': ['Password reset failed. Please try again.']}
                }
            }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
