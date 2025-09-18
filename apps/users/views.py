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
        refresh = RefreshToken.for_user(user)
        return Response({
            'success': True,
            'message': 'User created successfully',
            'user': UserProfileSerializer(user).data,
            'tokens': {
                'refresh': str(refresh),
                'access': str(refresh.access_token),
            }
        }, status=status.HTTP_201_CREATED)
    return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


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
                'refresh': str(refresh),
                'access': str(refresh.access_token),
            }
        }, status=status.HTTP_200_OK)
    return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


@api_view(['POST'])
@permission_classes([IsAuthenticated])
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
            return Response(
                {"detail": "If the email exists, password reset instructions will be sent."},
                status=status.HTTP_200_OK,
            )

        # Generate JWT token with UNIX timestamp
        exp = datetime.utcnow() + timedelta(hours=1)
        token_payload = {
            "user_id": user.id,
            "exp": exp.timestamp(),  # UNIX timestamp
        }
        token = jwt.encode(token_payload, settings.SECRET_KEY, algorithm="HS256")
        if isinstance(token, bytes):
            token = token.decode("utf-8")

        # Send token to frontend 
        return Response(
            {
                "detail": "If the email exists, password reset instructions will be sent.",
                "reset_token": token  # Frontend will build the reset link and send email
            },
            status=status.HTTP_200_OK,
        )


# PATCH /api/v1/users/resetPassword/<str:resetToken>/
class ResetPasswordView(generics.GenericAPIView):
    serializer_class = ResetPasswordSerializer
    permission_classes = []  # No auth needed

    def patch(self, request, resetToken, *args, **kwargs):
        try:
            payload = jwt.decode(resetToken, settings.SECRET_KEY, algorithms=["HS256"])
            user_id = payload.get("user_id")
        except jwt.ExpiredSignatureError:
            return Response({"detail": "Reset token has expired."}, status=status.HTTP_400_BAD_REQUEST)
        except jwt.InvalidTokenError:
            return Response({"detail": "Invalid reset token."}, status=status.HTTP_400_BAD_REQUEST)

        user = User.objects.filter(id=user_id).first()
        if not user:
            return Response({"detail": "User not found."}, status=status.HTTP_404_NOT_FOUND)

        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)

        user.set_password(serializer.validated_data["password"])
        user.save()

        return Response({"detail": "Password has been reset successfully."}, status=status.HTTP_200_OK)


# PATCH /api/v1/users/updatePassword
class UpdatePasswordView(generics.GenericAPIView):
    serializer_class = UpdatePasswordSerializer
    permission_classes = [IsAuthenticated]

    def patch(self, request, *args, **kwargs):
        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)

        user = request.user
        user.set_password(serializer.validated_data["new_password"])
        user.save()

        return Response({"detail": "Password updated successfully."}, status=status.HTTP_200_OK)