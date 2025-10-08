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
    from utils.error_handler import ErrorCodes, ERROR_MESSAGES, error_response
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
        return error_response(logger, "Token refresh failed", e)


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

# GET /api/v1/users/disposer-dashboard/
class DisposerDashboardView(generics.GenericAPIView):
    """
    NEW Disposer dashboard endpoint that fetches data directly from the database.
    No Node.js API calls - all data comes from direct ORM queries.

    Returns:
        - User profile data (from User table - Django managed)
        - Total listings created by this disposer (from Listing table - Node managed)
        - Sold listings count (from MarketplaceListing table - Node managed)
        - Recent 5 posts by this disposer (from Listing table - Node managed)
    """
    permission_classes = [IsAuthenticated]

    @rate_limit(key_func=user_key('dashboard'), rate=30, per=60)
    def get(self, request):
        """
        Get disposer dashboard data with direct database queries.
        """
        from apps.listings.models import Listing
        from apps.marketplace.models import MarketplaceListing

        user = request.user

        # 1. Get user profile data (Django-managed User table)
        serializer = UserProfileSerializer(user)
        user_data = serializer.data

        # 2. Get total listings created by this disposer (Node-managed Listing table)
        total_listings = Listing.objects.filter(user_id=user).count()

        # 3. Get sold listings count (Node-managed MarketplaceListing table)
        # A listing is "sold" when it has a marketplace entry with escrow_status='released'
        sold_listings = MarketplaceListing.objects.filter(
            listing_id__user_id=user,
            escrow_status='released'
        ).count()

        # 4. Get recent 5 posts by this disposer (Node-managed Listing table)
        recent_posts = Listing.objects.filter(
            user_id=user
        ).order_by('-created_at')[:5].values(
            'id',
            'title',
            'waste_type',
            'quantity',
            'status',
            'reward_estimate',
            'image_url',
            'created_at'
        )

        # Convert UUID to string for JSON serialization
        recent_posts_list = [
            {
                'id': str(post['id']),
                'title': post['title'],
                'waste_type': post['waste_type'],
                'quantity': post['quantity'],
                'status': post['status'],
                'reward_estimate': str(post['reward_estimate']),
                'image_url': post['image_url'],
                'created_at': post['created_at'].isoformat()
            }
            for post in recent_posts
        ]

        # 5. Construct response
        dashboard_data = {
            'user': user_data,
            'stats': {
                'total_listings': total_listings,
                'sold_listings': sold_listings,
                'recent_posts': recent_posts_list
            }
        }

        logger.info(
            f"Disposer dashboard accessed by user {user.id}",
            extra={
                'user_id': str(user.id),
                'total_listings': total_listings,
                'sold_listings': sold_listings
            }
        )

        return Response(dashboard_data, status=status.HTTP_200_OK)


# GET /api/v1/users/recycler-dashboard/
class RecyclerDashboardView(generics.GenericAPIView):
    """
    NEW Recycler dashboard endpoint that fetches data directly from the database.
    No Node.js API calls - all data comes from direct ORM queries.

    Returns:
        - User profile data (from User table - Django managed)
        - Total kg collected by this recycler (from MarketplaceListing table - Node managed)
        - Total points accumulated (from Wallet table - Django managed)
        - Recent 5 system-wide disposer listings (from Listing table - Node managed)
    """
    permission_classes = [IsAuthenticated]

    @rate_limit(key_func=user_key('dashboard'), rate=30, per=60)
    def get(self, request):
        """
        Get recycler dashboard data with direct database queries.
        """
        from apps.listings.models import Listing
        from apps.marketplace.models import MarketplaceListing
        from apps.wallet.models import Wallet
        from django.db.models import Sum

        user = request.user

        # 1. Get user profile data (Django-managed User table)
        serializer = UserProfileSerializer(user)
        user_data = serializer.data

        # 2. Get total kg collected by this recycler (Node-managed MarketplaceListing + Listing tables)
        # Sum up the quantity from all listings that this recycler has purchased
        total_kg_collected = MarketplaceListing.objects.filter(
            recycler_id=user,
            escrow_status='released'
        ).aggregate(
            total_kg=Sum('listing_id__quantity')
        )['total_kg'] or 0

        # 3. Get total points from wallet (Django-managed Wallet table)
        try:
            wallet = Wallet.objects.get(user=user)
            total_points = wallet.points
        except Wallet.DoesNotExist:
            total_points = 0
            logger.warning(f"No wallet found for user {user.id}")

        # 4. Get recent 5 system-wide disposer listings (Node-managed Listing table)
        # Show all pending/active listings across the platform
        recent_posts = Listing.objects.filter(
            status__in=['pending', 'accepted']
        ).order_by('-created_at')[:5].values(
            'id',
            'title',
            'waste_type',
            'quantity',
            'status',
            'reward_estimate',
            'image_url',
            'pickup_location',
            'created_at'
        )

        # Convert UUID to string for JSON serialization
        recent_posts_list = [
            {
                'id': str(post['id']),
                'title': post['title'],
                'waste_type': post['waste_type'],
                'quantity': post['quantity'],
                'status': post['status'],
                'reward_estimate': str(post['reward_estimate']),
                'image_url': post['image_url'],
                'pickup_location': post['pickup_location'],
                'created_at': post['created_at'].isoformat()
            }
            for post in recent_posts
        ]

        # 5. Construct response
        dashboard_data = {
            'user': user_data,
            'stats': {
                'total_kg_collected': float(total_kg_collected),
                'total_points': total_points,
                'recent_posts': recent_posts_list
            }
        }

        logger.info(
            f"Recycler dashboard accessed by user {user.id}",
            extra={
                'user_id': str(user.id),
                'total_kg_collected': float(total_kg_collected),
                'total_points': total_points
            }
        )

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
            return error_response(logger, f"Password reset failed for {email}", e)
