"""
URL configuration for wallet app.

Defines API endpoints for wallet operations including balance, transactions, and statistics.
"""
from django.urls import path
from . import views

app_name = 'wallet'

urlpatterns = [
    # Wallet balance and summary endpoints
    path('balance/', views.WalletBalanceView.as_view(), name='wallet-balance'),
    path('summary/', views.WalletSummaryView.as_view(), name='wallet-summary'),
    path('stats/', views.wallet_stats, name='wallet-stats'),
    
    # Transaction endpoints
    path('transactions/', views.WalletTransactionsView.as_view(), name='wallet-transactions'),
    path('transactions/<uuid:transaction_id>/', views.WalletTransactionDetailView.as_view(), name='transaction-detail'),
]