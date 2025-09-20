from django.urls import path
from . import views

urlpatterns = [
    path('send/', views.send_otp, name='send_otp'),
    path('verify/', views.verify_otp, name='verify_otp'),
    path('resend/', views.resend_otp, name='resend_otp'),
    path('request-password-reset/', views.request_password_reset, name='request_password_reset'),
]