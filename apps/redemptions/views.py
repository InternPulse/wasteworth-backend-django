from rest_framework import generics, status
from rest_framework.response import Response
from rest_framework.permissions import IsAuthenticated
from wallet.models import WalletTransaction
from .serializers import (
    RedemptionOptionSerializer,
    RedeemPointsSerializer,
    RedemptionHistorySerializer
)

# 6. GET redemption options
class RedemptionOptionsView(generics.GenericAPIView):
    permission_classes = [IsAuthenticated]

    def get(self, request):
        options = [
            {"redemption_type": "airtime", "points": 100},
            {"redemption_type": "voucher", "points": 200},
        ]
        serializer = RedemptionOptionSerializer(options, many=True)
        return Response(serializer.data, status=status.HTTP_200_OK)


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
            return Response(
                {"error": "Not enough points"},
                status=status.HTTP_400_BAD_REQUEST
            )

        # Deduct points
        wallet.points -= points
        wallet.save()

        # Create a transaction
        transaction = WalletTransaction.objects.create(
            user=request.user,
            transaction_type='redeem',
            points=points,
            payment_method=option,  # 'airtime' or 'voucher'
            status='pending'
        )

        return Response({
            "message": f"Redeemed {points} points for {option}",
            "transaction_id": transaction.transaction_id,
            "wallet": wallet_data  # updated balance + points returned here
        }, status=status.HTTP_201_CREATED)


# 8. GET redemption history
class RedemptionHistoryView(generics.ListAPIView):
    serializer_class = RedemptionHistorySerializer
    permission_classes = [IsAuthenticated]

    def get_queryset(self):
        return WalletTransaction.objects.filter(
            user=self.request.user,
            transaction_type="redeem"
        ).order_by("-created_at")

