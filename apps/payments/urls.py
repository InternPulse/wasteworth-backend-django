from django.urls import path
from . import views

urlpatterns = [
    # Payment flow
    path('initialize/', views.initialize_payment, name='initialize-payment'),
    path('verify/', views.verify_payment, name='verify-payment'),
    path('webhook/', views.paystack_webhook, name='paystack-webhook'),

    # Confirmation flow
    path('confirm-release/', views.confirm_item_released, name='confirm-item-released'),
    path('confirm-receipt/', views.confirm_item_received, name='confirm-item-received'),
]
