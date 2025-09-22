from rest_framework import generics, status
from rest_framework.decorators import api_view, permission_classes
from rest_framework.permissions import IsAuthenticated
from rest_framework.response import Response
from rest_framework_simplejwt.tokens import RefreshToken
from rest_framework_simplejwt.exceptions import TokenError
from django.contrib.auth import authenticate, get_user_model
from django.conf import settings
from datetime import datetime, timedelta
import jwt

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
    ForgotPasswordSerializer,
    ResetPasswordSerializer,
    UpdatePasswordSerializer,
)

User = get_user_model()

# ------------------------------
# User Authentication Views (Function-based)
# ------------------------------
@api_view(['POST'])
def signup(request):
    serializer = UserSignupSerializer(data=request.data)
    if serializer.is_valid():
        user = serializer.save()

        # Set user as unverified by default
        user.is_verified = False
        user.save()

        # Send OTP for verification
        try:
            from utils.otp import generate_and_send_otp
            otp_instance = generate_and_send_otp(user, 'signup')

            return Response({
                'success': True,
                'message': 'Account created successfully. Please verify your email with the OTP sent to complete registration.',
                'user_id': str(user.id),
                'email': user.email,
                'is_verified': user.is_verified,
                'otp_sent': True,
                'next_step': 'Verify OTP using POST /api/v1/otp/verify/?action=signup to get access tokens'
            }, status=status.HTTP_201_CREATED)

        except Exception as e:
            return Response({
                'success': True,
                'message': 'Account created successfully, but failed to send verification OTP.',
                'user_id': str(user.id),
                'email': user.email,
                'is_verified': user.is_verified,
                'otp_sent': False,
                'error': 'Failed to send OTP. Use POST /api/v1/otp/send/ to request verification OTP.'
            }, status=status.HTTP_201_CREATED)

    return Response({
        'success': False,
        'errors': serializer.errors
    }, status=status.HTTP_400_BAD_REQUEST)


@api_view(['POST'])
def login(request):
    serializer = UserLoginSerializer(data=request.data)
    if serializer.is_valid():
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
    return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


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

# POST /api/v1/users/forgotPassword
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

        # Send OTP for password reset
        try:
            from utils.otp import generate_and_send_otp
            otp_instance = generate_and_send_otp(user, 'reset')

            return Response({
                "success": True,
                "message": "If the email exists, password reset instructions will be sent.",
                "next_step": "Use POST /api/v1/otp/verify/?action=reset with email, otp, and new_password"
            }, status=status.HTTP_200_OK)

        except Exception as e:
            return Response({
                "success": False,
                "error": "Failed to send password reset instructions. Please try again."
            }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)


# PATCH /api/v1/users/resetPassword/<str:resetToken>/
# class ResetPasswordView(generics.GenericAPIView):
#     serializer_class = ResetPasswordSerializer
#     permission_classes = []  # No auth needed

#     def patch(self, request, resetToken, *args, **kwargs):
#         try:
#             payload = jwt.decode(resetToken, settings.SECRET_KEY, algorithms=["HS256"])
#             user_id = payload.get("user_id")
#         except jwt.ExpiredSignatureError:
#             return Response({"detail": "Reset token has expired."}, status=status.HTTP_400_BAD_REQUEST)
#         except jwt.InvalidTokenError:
#             return Response({"detail": "Invalid reset token."}, status=status.HTTP_400_BAD_REQUEST)

#         user = User.objects.filter(id=user_id).first()
#         if not user:
#             return Response({"detail": "User not found."}, status=status.HTTP_404_NOT_FOUND)

#         serializer = self.get_serializer(data=request.data)
#         serializer.is_valid(raise_exception=True)

#         user.set_password(serializer.validated_data["password"])
#         user.save()

#         return Response({"detail": "Password has been reset successfully."}, status=status.HTTP_200_OK)


# PATCH /api/v1/users/updatePassword
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
                return Response({
                    'success': False,
                    'error': 'old_password is required to send OTP'
                }, status=status.HTTP_400_BAD_REQUEST)

            user = request.user

            # Verify current password
            if not user.check_password(old_password):
                return Response({
                    'success': False,
                    'error': 'Current password is incorrect'
                }, status=status.HTTP_400_BAD_REQUEST)

            # Send OTP
            try:
                from utils.otp import generate_and_send_otp
                otp_instance = generate_and_send_otp(user, 'reset')

                return Response({
                    'success': True,
                    'message': 'OTP sent to your email. Please provide OTP and new_password to complete password update.',
                    'otp_id': str(otp_instance.id)
                }, status=status.HTTP_200_OK)
            except Exception as e:
                return Response({
                    'success': False,
                    'error': 'Failed to send OTP. Please try again.'
                }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

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
            if not otp_serializer.is_valid():
                return Response({
                    'success': False,
                    'errors': otp_serializer.errors
                }, status=status.HTTP_400_BAD_REQUEST)

            otp_user = otp_serializer.validated_data['user']
            otp_obj = otp_serializer.validated_data['otp_obj']

            # Ensure OTP is for password reset and belongs to authenticated user
            if otp_obj.purpose != 'reset':
                return Response({
                    'success': False,
                    'error': 'OTP is not for password reset'
                }, status=status.HTTP_400_BAD_REQUEST)

            if otp_user.id != user.id:
                return Response({
                    'success': False,
                    'error': 'OTP does not belong to authenticated user'
                }, status=status.HTTP_403_FORBIDDEN)

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