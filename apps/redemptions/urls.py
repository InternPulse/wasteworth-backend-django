from django.urls import path
from .views import RedemptionOptionsView, RedeemPointsView, RedemptionHistoryView

urlpatterns = [
    path('redemption-options/', RedemptionOptionsView.as_view(), name='redemption-options'),
    path('redeem/', RedeemPointsView.as_view(), name='redeem-points'),
    path('redemption-history/', RedemptionHistoryView.as_view(), name='redemption-history'),
]
