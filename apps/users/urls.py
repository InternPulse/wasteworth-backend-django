from django.urls import path
from .views import ForgotPasswordView, ResetPasswordView, UpdatePasswordView

urlpatterns = [
    path('forgotPassword/', ForgotPasswordView.as_view(), name='forgot_password'),
    path('resetPassword/<str:resetToken>/', ResetPasswordView.as_view(), name='reset_password'),
    path('updatePassword/', UpdatePasswordView.as_view(), name='update_password'),
]
