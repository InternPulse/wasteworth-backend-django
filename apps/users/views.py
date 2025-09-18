from rest_framework import generics, status
from rest_framework.response import Response
from rest_framework.permissions import IsAuthenticated
from django.contrib.auth import get_user_model
from django.conf import settings
from datetime import datetime, timedelta
import jwt

from .serializers import (
    ForgotPasswordSerializer,
    ResetPasswordSerializer,
    UpdatePasswordSerializer,
)

User = get_user_model()

# ------------------------------
# POST /api/v1/users/forgotPassword
# ------------------------------
class ForgotPasswordView(generics.GenericAPIView):
    serializer_class = ForgotPasswordSerializer
    permission_classes = []  # No auth needed

    def post(self, request, *args, **kwargs):
        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)

        email = serializer.validated_data["email"]
        user = User.objects.filter(email=email).first()

        # Always return generic message
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

# ------------------------------
# PATCH /api/v1/users/resetPassword/<str:resetToken>/
# ------------------------------
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

# ------------------------------
# PATCH /api/v1/users/updatePassword
# ------------------------------
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