from django.urls import path
from .views import RedemptionOptionsView, RedeemPointsView, RedemptionHistoryView

urlpatterns = [
    path('points/redemption-options/', RedemptionOptionsView.as_view(), name='redemption-options'),
    path('points/redeem/', RedeemPointsView.as_view(), name='redeem-points'),
    path('points/redemption-history/', RedemptionHistoryView.as_view(), name='redemption-history'),
]
