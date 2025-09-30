from django.shortcuts import render
from rest_framework import generics, status
from rest_framework.decorators import api_view, permission_classes
from rest_framework.permissions import IsAuthenticated
from rest_framework.response import Response
from rest_framework.pagination import PageNumberPagination
from django.db.models import Sum, Q
from django.shortcuts import get_object_or_404
import logging

# Import error handler if it exists, following the same pattern as users/views.py
try:
    from utils.error_handler import ErrorCodes, ERROR_MESSAGES
except ImportError:
    # Fallback error handling if utils.error_handler doesn't exist
    class ErrorCodes:
        VALIDATION_ERROR = 'VALIDATION_ERROR'
        NOT_FOUND = 'NOT_FOUND'
        PERMISSION_DENIED = 'PERMISSION_DENIED'
        SERVER_ERROR = 'SERVER_ERROR'
    
    ERROR_MESSAGES = {
        ErrorCodes.VALIDATION_ERROR: "The provided data is invalid. Please check the details below.",
        ErrorCodes.NOT_FOUND: "The requested resource was not found.",
        ErrorCodes.PERMISSION_DENIED: "You do not have permission to access this resource.",
        ErrorCodes.SERVER_ERROR: "An internal server error occurred. Please try again later."
    }

from .models import Wallet, WalletTransaction
from .serializers import (
    WalletSerializer,
    TransactionSerializer,
    WalletSummarySerializer,
    TransactionFilterSerializer,RedeemPointsSerializer,RedemptionHistorySerializer,RedemptionOptionSerializer
)

logger = logging.getLogger(__name__)

# Custom pagination class following project patterns
class WalletTransactionPagination(PageNumberPagination):
    page_size = 20
    page_size_query_param = 'page_size'
    max_page_size = 100


# ------------------------------
# Wallet Balance Views
# ------------------------------

# GET /api/v1/wallet/balance/
class WalletBalanceView(generics.GenericAPIView):
    """
    Get authenticated user's wallet balance and basic information.
    Follows the same pattern as UserDashboardView.
    """
    serializer_class = WalletSerializer
    permission_classes = [IsAuthenticated]

    def get(self, request):
        try:
            # Get or create wallet for authenticated user
            wallet, created = Wallet.objects.get_or_create(
                user=request.user,
                defaults={
                    'balance': 0.00,
                    'currency': 'NGN',
                    'points': 0,
                    'is_active': True
                }
            )

            if created:
                logger.info(f"Created new wallet for user {request.user.email}")

            serializer = self.serializer_class(wallet)
            return Response({
                'success': True,
                'message': 'Wallet balance retrieved successfully',
                'wallet': serializer.data
            }, status=status.HTTP_200_OK)

        except Exception as e:
            logger.error(f"Error retrieving wallet for user {request.user.email}: {str(e)}")
            return Response({
                'success': False,
                'message': ERROR_MESSAGES[ErrorCodes.SERVER_ERROR],
                'error': {
                    'code': ErrorCodes.SERVER_ERROR,
                    'message': ERROR_MESSAGES[ErrorCodes.SERVER_ERROR],
                    'details': {'error': ['Failed to retrieve wallet information.']}
                }
            }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)


# GET /api/v1/wallet/summary/
class WalletSummaryView(generics.GenericAPIView):
    """
    Get comprehensive wallet summary with recent transactions and statistics.
    Similar to dashboard-style views in the project.
    """
    serializer_class = WalletSummarySerializer
    permission_classes = [IsAuthenticated]

    def get(self, request):
        try:
            # Get or create wallet for authenticated user
            wallet, created = Wallet.objects.get_or_create(
                user=request.user,
                defaults={
                    'balance': 0.00,
                    'currency': 'NGN',
                    'points': 0,
                    'is_active': True
                }
            )
            
            # Get recent transactions (last 10)
            recent_transactions = WalletTransaction.objects.filter(
                wallet=wallet
            ).select_related('user', 'wallet')[:10]
            
            # Calculate statistics
            all_transactions = WalletTransaction.objects.filter(wallet=wallet)
            
            total_transactions = all_transactions.count()
            total_credits = all_transactions.filter(
                transaction_type__in=['credit', 'deposit', 'referral_reward', 'activity_reward', 'refund']
            ).aggregate(total=Sum('amount'))['total'] or 0
            
            total_debits = all_transactions.filter(
                transaction_type__in=['debit', 'withdrawal', 'payout']
            ).aggregate(total=Sum('amount'))['total'] or 0
            
            total_points_earned = all_transactions.filter(
                transaction_type__in=['referral_reward', 'activity_reward']
            ).aggregate(total=Sum('points'))['total'] or 0
            
            total_points_redeemed = all_transactions.filter(
                transaction_type='redeem'
            ).aggregate(total=Sum('points'))['total'] or 0
            
            # Prepare summary data
            summary_data = {
                'wallet': wallet,
                'recent_transactions': recent_transactions,
                'total_transactions': total_transactions,
                'total_credits': total_credits,
                'total_debits': total_debits,
                'total_points_earned': total_points_earned,
                'total_points_redeemed': total_points_redeemed
            }
            
            serializer = self.serializer_class(summary_data)
            return Response({
                'success': True,
                'message': 'Wallet summary retrieved successfully',
                'data': serializer.data
            }, status=status.HTTP_200_OK)

        except Exception as e:
            logger.error(f"Error retrieving wallet summary for user {request.user.email}: {str(e)}")
            return Response({
                'success': False,
                'message': ERROR_MESSAGES[ErrorCodes.SERVER_ERROR],
                'error': {
                    'code': ErrorCodes.SERVER_ERROR,
                    'message': ERROR_MESSAGES[ErrorCodes.SERVER_ERROR],
                    'details': {'error': ['Failed to retrieve wallet summary.']}
                }
            }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)


# ------------------------------
# Wallet Transactions Views
# ------------------------------

# GET /api/v1/wallet/transactions/
class WalletTransactionsView(generics.ListAPIView):
    """
    Get paginated list of wallet transactions with filtering support.
    Follows the same pattern as other list views in the project.
    """
    serializer_class = TransactionSerializer
    permission_classes = [IsAuthenticated]
    pagination_class = WalletTransactionPagination

    def get_queryset(self):
        """
        Filter transactions for authenticated user's wallet.
        Supports filtering by transaction type, status, payment method, date range, and amount range.
        """
        try:
            # Get user's wallet
            wallet = get_object_or_404(Wallet, user=self.request.user)
            
            # Base queryset
            queryset = WalletTransaction.objects.filter(
                wallet=wallet
            ).select_related('user', 'wallet').order_by('-created_at')
            
            # Apply filters based on query parameters
            transaction_type = self.request.query_params.get('transaction_type')
            if transaction_type:
                queryset = queryset.filter(transaction_type=transaction_type)
            
            payment_method = self.request.query_params.get('payment_method')
            if payment_method:
                queryset = queryset.filter(payment_method=payment_method)
            
            status_filter = self.request.query_params.get('status')
            if status_filter:
                queryset = queryset.filter(status=status_filter)
            
            # Date range filtering
            date_from = self.request.query_params.get('date_from')
            date_to = self.request.query_params.get('date_to')
            
            if date_from:
                queryset = queryset.filter(created_at__gte=date_from)
            if date_to:
                queryset = queryset.filter(created_at__lte=date_to)
            
            # Amount range filtering
            min_amount = self.request.query_params.get('min_amount')
            max_amount = self.request.query_params.get('max_amount')
            
            if min_amount:
                queryset = queryset.filter(amount__gte=min_amount)
            if max_amount:
                queryset = queryset.filter(amount__lte=max_amount)
            
            # Search by description or reference
            search = self.request.query_params.get('search')
            if search:
                queryset = queryset.filter(
                    Q(description__icontains=search) |
                    Q(reference__icontains=search)
                )
            
            return queryset
            
        except Wallet.DoesNotExist:
            logger.warning(f"Wallet not found for user {self.request.user.email}")
            return WalletTransaction.objects.none()
        except Exception as e:
            logger.error(f"Error filtering transactions for user {self.request.user.email}: {str(e)}")
            return WalletTransaction.objects.none()

    def list(self, request, *args, **kwargs):
        """
        Override list method to add filtering validation and custom response format.
        Follows the same pattern as other API views in the project.
        """
        try:
            # Validate filter parameters
            filter_serializer = TransactionFilterSerializer(data=request.query_params)
            if not filter_serializer.is_valid():
                return Response({
                    'success': False,
                    'error': {
                        'code': ErrorCodes.VALIDATION_ERROR,
                        'message': ERROR_MESSAGES[ErrorCodes.VALIDATION_ERROR],
                        'details': filter_serializer.errors
                    }
                }, status=status.HTTP_400_BAD_REQUEST)
            
            # Get paginated results
            queryset = self.filter_queryset(self.get_queryset())
            page = self.paginate_queryset(queryset)
            
            if page is not None:
                serializer = self.get_serializer(page, many=True)
                paginated_response = self.get_paginated_response(serializer.data)
                
                # Add success field to match project response format
                paginated_response.data = {
                    'success': True,
                    'message': f'Retrieved {len(serializer.data)} transactions',
                    **paginated_response.data
                }
                return paginated_response
            
            serializer = self.get_serializer(queryset, many=True)
            return Response({
                'success': True,
                'message': f'Retrieved {len(serializer.data)} transactions',
                'results': serializer.data,
                'count': len(serializer.data)
            }, status=status.HTTP_200_OK)
            
        except Exception as e:
            logger.error(f"Error listing transactions for user {request.user.email}: {str(e)}")
            return Response({
                'success': False,
                'error': {
                    'code': ErrorCodes.SERVER_ERROR,
                    'message': ERROR_MESSAGES[ErrorCodes.SERVER_ERROR],
                    'details': {'error': ['Failed to retrieve transactions.']}
                }
            }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)


# GET /api/v1/wallet/transactions/<transaction_id>/
class WalletTransactionDetailView(generics.GenericAPIView):
    """
    Get detailed information about a specific transaction.
    Follows the same pattern as detail views in the project.
    """
    serializer_class = TransactionSerializer
    permission_classes = [IsAuthenticated]

    def get(self, request, transaction_id):
        try:
            # Get user's wallet
            wallet = get_object_or_404(Wallet, user=request.user)
            
            # Get specific transaction
            transaction = get_object_or_404(
                WalletTransaction,
                transaction_id=transaction_id,
                wallet=wallet
            )
            
            serializer = self.serializer_class(transaction)
            return Response({
                'success': True,
                'message': 'Transaction details retrieved successfully',
                'transaction': serializer.data
            }, status=status.HTTP_200_OK)
            
        except WalletTransaction.DoesNotExist:
            return Response({
                'success': False,
                'error': {
                    'code': ErrorCodes.NOT_FOUND,
                    'message': 'Transaction not found or you do not have permission to view it.',
                    'details': {'transaction_id': ['Invalid transaction ID or permission denied.']}
                }
            }, status=status.HTTP_404_NOT_FOUND)
        except Exception as e:
            logger.error(f"Error retrieving transaction {transaction_id} for user {request.user.email}: {str(e)}")
            return Response({
                'success': False,
                'error': {
                    'code': ErrorCodes.SERVER_ERROR,
                    'message': ERROR_MESSAGES[ErrorCodes.SERVER_ERROR],
                    'details': {'error': ['Failed to retrieve transaction details.']}
                }
            }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)


# ------------------------------
# Wallet Statistics Views
# ------------------------------

# GET /api/v1/wallet/stats/
@api_view(['GET'])
@permission_classes([IsAuthenticated])
def wallet_stats(request):
    """
    Get wallet statistics for authenticated user.
    Follows the same function-based view pattern as auth endpoints.
    """
    try:
        # Get user's wallet
        wallet = get_object_or_404(Wallet, user=request.user)
        
        # Calculate various statistics
        all_transactions = WalletTransaction.objects.filter(wallet=wallet)
        
        # Transaction counts by type
        transaction_counts = {}
        for choice in WalletTransaction.TRANSACTION_TYPE_CHOICES:
            transaction_type = choice[0]
            count = all_transactions.filter(transaction_type=transaction_type).count()
            transaction_counts[transaction_type] = count
        
        # Transaction counts by status
        status_counts = {}
        for choice in WalletTransaction.STATUS_CHOICES:
            status_type = choice[0]
            count = all_transactions.filter(status=status_type).count()
            status_counts[status_type] = count
        
        # Monthly transaction summary (last 12 months)
        from django.utils import timezone
        from datetime import timedelta
        import calendar
        
        current_date = timezone.now()
        monthly_stats = []
        
        for i in range(12):
            month_start = current_date.replace(day=1) - timedelta(days=i*30)
            month_end = (month_start.replace(month=month_start.month % 12 + 1, day=1) - timedelta(days=1)) if month_start.month != 12 else month_start.replace(year=month_start.year + 1, month=1, day=1) - timedelta(days=1)
            
            month_transactions = all_transactions.filter(
                created_at__range=[month_start, month_end]
            )
            
            monthly_stats.append({
                'month': calendar.month_name[month_start.month],
                'year': month_start.year,
                'total_transactions': month_transactions.count(),
                'total_amount': month_transactions.aggregate(Sum('amount'))['amount__sum'] or 0,
                'total_points': month_transactions.aggregate(Sum('points'))['points__sum'] or 0
            })
        
        return Response({
            'success': True,
            'message': 'Wallet statistics retrieved successfully',
            'stats': {
                'wallet_balance': wallet.balance,
                'wallet_points': wallet.points,
                'total_transactions': all_transactions.count(),
                'transaction_counts_by_type': transaction_counts,
                'transaction_counts_by_status': status_counts,
                'monthly_summary': monthly_stats[:6]  # Last 6 months
            }
        }, status=status.HTTP_200_OK)
        
    except Wallet.DoesNotExist:
        return Response({
            'success': False,
            'error': {
                'code': ErrorCodes.NOT_FOUND,
                'message': 'Wallet not found for authenticated user.',
                'details': {'wallet': ['No wallet associated with your account.']}
            }
        }, status=status.HTTP_404_NOT_FOUND)
    except Exception as e:
        logger.error(f"Error retrieving wallet stats for user {request.user.email}: {str(e)}")
        return Response({
            'success': False,
            'error': {
                'code': ErrorCodes.SERVER_ERROR,
                'message': ERROR_MESSAGES[ErrorCodes.SERVER_ERROR],
                'details': {'error': ['Failed to retrieve wallet statistics.']}
            }
        }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
    

class RedemptionOptionsView(generics.GenericAPIView):
    permission_classes = [IsAuthenticated]

    def get(self, request):
        options = [
            {"redemption_type": "airtime", "points": 100},
            {"redemption_type": "voucher", "points": 200},
        ]
        serializer = RedemptionOptionSerializer(options, many=True)
        return Response({
            'success': True,
            'message': 'Redemption options retrieved successfully',
            'options': serializer.data
        }, status=status.HTTP_200_OK)


# 7. POST redeem points
class RedeemPointsView(generics.GenericAPIView):
    serializer_class = RedeemPointsSerializer
    permission_classes = [IsAuthenticated]

    def post(self, request):
        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)

        option = serializer.validated_data['option']
        points = serializer.validated_data['points']

        wallet = request.user.wallet
        if wallet.points < points:
            return Response({
                'success': False,
                'message': 'You do not have enough points for this redemption',
                'error': {
                    'code': 'INSUFFICIENT_POINTS',
                    'message': 'You do not have enough points for this redemption',
                    'details': {
                        'points': [f'Required: {points} points, Available: {wallet.points} points']
                    }
                }
            }, status=status.HTTP_400_BAD_REQUEST)

        # Deduct points
        wallet.points -= points
        wallet.save()

        # Create a transaction
        transaction = WalletTransaction.objects.create(
            wallet=wallet,
            user=request.user,
            transaction_type='redeem',
            points=points,
            payment_method=option,  # 'airtime' or 'voucher'
            status='pending'
        )

        return Response({
            'success': True,
            'message': f'Successfully redeemed {points} points for {option}',
            'transaction_id': transaction.transaction_id,
            'wallet': WalletSerializer(wallet).data
        }, status=status.HTTP_201_CREATED)