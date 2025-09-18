from django.urls import path
from . import views
from .views import ForgotPasswordView, ResetPasswordView, UpdatePasswordView

app_name = 'users'

urlpatterns = [
    # User Authentication
    path('signup/', views.signup, name='signup'),
    path('login/', views.login, name='login'),
    path('logout/', views.logout, name='logout'),
    
    # Password Management
    path('forgotPassword/', ForgotPasswordView.as_view(), name='forgot_password'),
    path('resetPassword/<str:resetToken>/', ResetPasswordView.as_view(), name='reset_password'),
    path('updatePassword/', UpdatePasswordView.as_view(), name='update_password'),
]
