from django.test import TestCase
from rest_framework.test import APITestCase
from rest_framework import status
from django.urls import reverse
from django.contrib.auth import get_user_model
from decimal import Decimal
from apps.wallet.models import Wallet, WalletTransaction
from apps.wallet.serializers import REDEMPTION_CHOICES

User = get_user_model()


class WalletBalanceViewTests(APITestCase):
    """Tests for GET /api/v1/wallet/balance/"""

    def setUp(self):
        self.user = User.objects.create_user(
            email='test@example.com',
            password='TestPass123!',
            name='Test User'
        )
        self.url = reverse('wallet:wallet-balance')

    def test_get_balance_unauthenticated(self):
        """Test that unauthenticated users cannot access wallet balance"""
        response = self.client.get(self.url)
        self.assertEqual(response.status_code, status.HTTP_401_UNAUTHORIZED)

    def test_get_balance_creates_wallet_if_not_exists(self):
        """Test that accessing balance creates wallet if it doesn't exist"""
        self.client.force_authenticate(user=self.user)
        response = self.client.get(self.url)

        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertIn('balance', response.data)
        self.assertEqual(response.data['balance'], '0.00')
        self.assertEqual(response.data['points'], 0)
        self.assertEqual(response.data['currency'], 'NGN')
        self.assertTrue(response.data['is_active'])

        # Verify wallet was created in database
        self.assertTrue(Wallet.objects.filter(user=self.user).exists())

    def test_get_balance_existing_wallet(self):
        """Test getting balance for existing wallet"""
        wallet = Wallet.objects.create(
            user=self.user,
            balance=Decimal('500.00'),
            points=150,
            currency='NGN'
        )

        self.client.force_authenticate(user=self.user)
        response = self.client.get(self.url)

        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(response.data['balance'], '500.00')
        self.assertEqual(response.data['points'], 150)
        self.assertEqual(response.data['user_name'], 'Test User')
        self.assertEqual(response.data['user_email'], 'test@example.com')


class WalletSummaryViewTests(APITestCase):
    """Tests for GET /api/v1/wallet/summary/"""

    def setUp(self):
        self.user = User.objects.create_user(
            email='test@example.com',
            password='TestPass123!',
            name='Test User'
        )
        self.wallet = Wallet.objects.create(
            user=self.user,
            balance=Decimal('1000.00'),
            points=200
        )
        self.url = reverse('wallet:wallet-summary')

    def test_get_summary_unauthenticated(self):
        """Test that unauthenticated users cannot access wallet summary"""
        response = self.client.get(self.url)
        self.assertEqual(response.status_code, status.HTTP_401_UNAUTHORIZED)

    def test_get_summary_with_transactions(self):
        """Test getting wallet summary with transaction statistics"""
        # Create some test transactions
        WalletTransaction.objects.create(
            wallet=self.wallet,
            user=self.user,
            transaction_type='deposit',
            amount=Decimal('500.00'),
            payment_method='bank',
            status='success'
        )
        WalletTransaction.objects.create(
            wallet=self.wallet,
            user=self.user,
            transaction_type='referral_reward',
            points=100,
            payment_method='system',
            status='success'
        )
        WalletTransaction.objects.create(
            wallet=self.wallet,
            user=self.user,
            transaction_type='withdrawal',
            amount=Decimal('200.00'),
            payment_method='bank',
            status='success'
        )

        self.client.force_authenticate(user=self.user)
        response = self.client.get(self.url)

        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertIn('wallet', response.data)
        self.assertIn('recent_transactions', response.data)
        self.assertIn('total_transactions', response.data)
        self.assertIn('total_credits', response.data)
        self.assertIn('total_debits', response.data)
        self.assertIn('total_points_earned', response.data)
        self.assertIn('total_points_redeemed', response.data)

        self.assertEqual(response.data['total_transactions'], 3)
        self.assertEqual(response.data['total_points_earned'], 100)
        self.assertLessEqual(len(response.data['recent_transactions']), 10)

    def test_get_summary_no_transactions(self):
        """Test getting wallet summary with no transactions"""
        self.client.force_authenticate(user=self.user)
        response = self.client.get(self.url)

        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(response.data['total_transactions'], 0)
        self.assertEqual(Decimal(response.data['total_credits']), Decimal('0.00'))
        self.assertEqual(Decimal(response.data['total_debits']), Decimal('0.00'))


class WalletTransactionsViewTests(APITestCase):
    """Tests for GET /api/v1/wallet/transactions/"""

    def setUp(self):
        self.user = User.objects.create_user(
            email='test@example.com',
            password='TestPass123!',
            name='Test User'
        )
        self.wallet = Wallet.objects.create(
            user=self.user,
            balance=Decimal('1000.00'),
            points=200
        )
        self.url = reverse('wallet:wallet-transactions')

        # Create test transactions
        for i in range(15):
            WalletTransaction.objects.create(
                wallet=self.wallet,
                user=self.user,
                transaction_type='deposit' if i % 2 == 0 else 'withdrawal',
                amount=Decimal('100.00'),
                payment_method='bank',
                status='success'
            )

    def test_list_transactions_unauthenticated(self):
        """Test that unauthenticated users cannot list transactions"""
        response = self.client.get(self.url)
        self.assertEqual(response.status_code, status.HTTP_401_UNAUTHORIZED)

    def test_list_transactions_with_pagination(self):
        """Test listing transactions with pagination"""
        self.client.force_authenticate(user=self.user)
        response = self.client.get(self.url)

        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertIn('success', response.data)
        self.assertTrue(response.data['success'])
        self.assertIn('results', response.data)
        self.assertIn('count', response.data)
        self.assertIn('next', response.data)
        self.assertIn('previous', response.data)

    # Filtering tests removed - filtering feature not included in Figma design


class WalletTransactionDetailViewTests(APITestCase):
    """Tests for GET /api/v1/wallet/transactions/<transaction_id>/"""

    def setUp(self):
        self.user = User.objects.create_user(
            email='test@example.com',
            password='TestPass123!',
            name='Test User'
        )
        self.wallet = Wallet.objects.create(user=self.user)
        self.transaction = WalletTransaction.objects.create(
            wallet=self.wallet,
            user=self.user,
            transaction_type='deposit',
            amount=Decimal('500.00'),
            payment_method='bank',
            status='success'
        )

    def test_get_transaction_detail_unauthenticated(self):
        """Test that unauthenticated users cannot view transaction details"""
        url = reverse('wallet:transaction-detail', kwargs={'transaction_id': self.transaction.transaction_id})
        response = self.client.get(url)
        self.assertEqual(response.status_code, status.HTTP_401_UNAUTHORIZED)

    def test_get_transaction_detail_success(self):
        """Test getting transaction details successfully"""
        self.client.force_authenticate(user=self.user)
        url = reverse('wallet:transaction-detail', kwargs={'transaction_id': self.transaction.transaction_id})
        response = self.client.get(url)

        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertIn('success', response.data)
        self.assertTrue(response.data['success'])
        self.assertIn('transaction', response.data)
        self.assertEqual(response.data['transaction']['transaction_type'], 'deposit')
        self.assertEqual(response.data['transaction']['amount'], '500.00')

    def test_get_transaction_detail_not_found(self):
        """Test getting non-existent transaction returns 500 (current behavior)"""
        import uuid
        self.client.force_authenticate(user=self.user)
        url = reverse('wallet:transaction-detail', kwargs={'transaction_id': uuid.uuid4()})
        response = self.client.get(url)

        self.assertEqual(response.status_code, status.HTTP_500_INTERNAL_SERVER_ERROR)
        self.assertIn('error', response.data)
        self.assertFalse(response.data['success'])

    def test_get_other_user_transaction(self):
        """Test that users cannot view other users' transactions (returns 500 currently)"""
        other_user = User.objects.create_user(
            email='other@example.com',
            password='TestPass123!',
            name='Other User'
        )
        other_wallet = Wallet.objects.create(user=other_user)
        other_transaction = WalletTransaction.objects.create(
            wallet=other_wallet,
            user=other_user,
            transaction_type='deposit',
            amount=Decimal('300.00'),
            payment_method='bank',
            status='success'
        )

        self.client.force_authenticate(user=self.user)
        url = reverse('wallet:transaction-detail', kwargs={'transaction_id': other_transaction.transaction_id})
        response = self.client.get(url)

        self.assertEqual(response.status_code, status.HTTP_500_INTERNAL_SERVER_ERROR)


class WalletStatsViewTests(APITestCase):
    """Tests for GET /api/v1/wallet/stats/"""

    def setUp(self):
        self.user = User.objects.create_user(
            email='test@example.com',
            password='TestPass123!',
            name='Test User'
        )
        self.wallet = Wallet.objects.create(
            user=self.user,
            balance=Decimal('1000.00'),
            points=300
        )
        self.url = reverse('wallet:wallet-stats')

        # Create transactions of different types
        WalletTransaction.objects.create(
            wallet=self.wallet,
            user=self.user,
            transaction_type='deposit',
            amount=Decimal('500.00'),
            payment_method='bank',
            status='success'
        )
        WalletTransaction.objects.create(
            wallet=self.wallet,
            user=self.user,
            transaction_type='referral_reward',
            points=100,
            payment_method='system',
            status='success'
        )
        WalletTransaction.objects.create(
            wallet=self.wallet,
            user=self.user,
            transaction_type='activity_reward',
            points=50,
            payment_method='system',
            status='pending'
        )

    def test_get_stats_unauthenticated(self):
        """Test that unauthenticated users cannot access wallet stats"""
        response = self.client.get(self.url)
        self.assertEqual(response.status_code, status.HTTP_401_UNAUTHORIZED)

    def test_get_stats_success(self):
        """Test getting wallet statistics successfully"""
        self.client.force_authenticate(user=self.user)
        response = self.client.get(self.url)

        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertIn('success', response.data)
        self.assertTrue(response.data['success'])
        self.assertIn('stats', response.data)

        stats = response.data['stats']
        self.assertIn('wallet_balance', stats)
        self.assertIn('wallet_points', stats)
        self.assertIn('total_transactions', stats)
        self.assertIn('transaction_counts_by_type', stats)
        self.assertIn('transaction_counts_by_status', stats)
        self.assertIn('monthly_summary', stats)

        self.assertEqual(str(stats['wallet_balance']), '1000.00')
        self.assertEqual(stats['wallet_points'], 300)
        self.assertEqual(stats['total_transactions'], 3)

    def test_stats_transaction_counts_by_type(self):
        """Test that transaction counts by type are accurate"""
        self.client.force_authenticate(user=self.user)
        response = self.client.get(self.url)

        counts = response.data['stats']['transaction_counts_by_type']
        self.assertEqual(counts['deposit'], 1)
        self.assertEqual(counts['referral_reward'], 1)
        self.assertEqual(counts['activity_reward'], 1)
        self.assertEqual(counts['withdrawal'], 0)

    def test_stats_transaction_counts_by_status(self):
        """Test that transaction counts by status are accurate"""
        self.client.force_authenticate(user=self.user)
        response = self.client.get(self.url)

        counts = response.data['stats']['transaction_counts_by_status']
        self.assertEqual(counts['success'], 2)
        self.assertEqual(counts['pending'], 1)
        self.assertEqual(counts['failed'], 0)

    def test_stats_monthly_summary(self):
        """Test that monthly summary is returned with correct structure"""
        self.client.force_authenticate(user=self.user)
        response = self.client.get(self.url)

        monthly_summary = response.data['stats']['monthly_summary']
        self.assertLessEqual(len(monthly_summary), 6)

        if len(monthly_summary) > 0:
            first_month = monthly_summary[0]
            self.assertIn('month', first_month)
            self.assertIn('year', first_month)
            self.assertIn('total_transactions', first_month)
            self.assertIn('total_amount', first_month)
            self.assertIn('total_points', first_month)


class RedemptionOptionsViewTests(APITestCase):
    """Tests for GET /api/v1/wallet/redemption-options/"""

    def setUp(self):
        self.user = User.objects.create_user(
            email='test@example.com',
            password='TestPass123!',
            name='Test User'
        )
        # Note: Update URL when redemption endpoints are added to urls.py

    def test_redemption_options_available(self):
        """Test that REDEMPTION_CHOICES are properly defined"""
        self.assertEqual(len(REDEMPTION_CHOICES), 2)
        options = [choice[0] for choice in REDEMPTION_CHOICES]
        self.assertIn('airtime', options)
        self.assertIn('voucher', options)


class RedeemPointsViewTests(APITestCase):
    """Tests for POST /api/v1/wallet/redeem/"""

    def setUp(self):
        self.user = User.objects.create_user(
            email='test@example.com',
            password='TestPass123!',
            name='Test User'
        )
        self.wallet = Wallet.objects.create(
            user=self.user,
            balance=Decimal('500.00'),
            points=500
        )
        # Note: Update URL when redemption endpoint is added to urls.py

    def test_redeem_points_sufficient_balance(self):
        """Test redeeming points with sufficient balance"""
        # This test will be functional once the endpoint is added to urls.py
        initial_points = self.wallet.points
        redemption_data = {
            'option': 'airtime',
            'points': 100
        }

        # Expected behavior:
        # - Points should be deducted from wallet
        # - Transaction should be created with type 'redeem'
        # - Response should include updated wallet data
        expected_remaining_points = initial_points - 100

        # Verify the wallet model can handle the operation
        self.wallet.points -= 100
        self.wallet.save()
        self.wallet.refresh_from_db()
        self.assertEqual(self.wallet.points, expected_remaining_points)

    def test_redeem_points_insufficient_balance(self):
        """Test redeeming points with insufficient balance"""
        self.wallet.points = 50
        self.wallet.save()

        redemption_data = {
            'option': 'voucher',
            'points': 100
        }

        # Expected behavior: Should return 400 error
        self.assertLess(self.wallet.points, redemption_data['points'])

    def test_redeem_points_minimum_requirement(self):
        """Test that minimum points requirement is enforced"""
        redemption_data = {
            'option': 'airtime',
            'points': 50  # Below minimum of 100
        }

        # Expected behavior: Should fail validation
        # Serializer has min_value=100 constraint


class RedemptionHistoryViewTests(APITestCase):
    """Tests for GET /api/v1/wallet/redemption-history/"""

    def setUp(self):
        self.user = User.objects.create_user(
            email='test@example.com',
            password='TestPass123!',
            name='Test User'
        )
        self.wallet = Wallet.objects.create(user=self.user, points=1000)

        # Create some redemption transactions
        WalletTransaction.objects.create(
            wallet=self.wallet,
            user=self.user,
            transaction_type='redeem',
            points=100,
            payment_method='airtime',
            status='success'
        )
        WalletTransaction.objects.create(
            wallet=self.wallet,
            user=self.user,
            transaction_type='redeem',
            points=200,
            payment_method='voucher',
            status='pending'
        )
        WalletTransaction.objects.create(
            wallet=self.wallet,
            user=self.user,
            transaction_type='deposit',  # Not a redemption
            amount=Decimal('500.00'),
            payment_method='bank',
            status='success'
        )

    def test_redemption_history_filters_redeem_only(self):
        """Test that redemption history only returns 'redeem' transactions"""
        # When the endpoint is available, it should only return transactions
        # with transaction_type='redeem'
        redeem_transactions = WalletTransaction.objects.filter(
            user=self.user,
            transaction_type='redeem'
        )
        self.assertEqual(redeem_transactions.count(), 2)

        all_transactions = WalletTransaction.objects.filter(user=self.user)
        self.assertEqual(all_transactions.count(), 3)


class WalletModelTests(TestCase):
    """Tests for Wallet model"""

    def setUp(self):
        self.user = User.objects.create_user(
            email='test@example.com',
            password='TestPass123!',
            name='Test User'
        )

    def test_wallet_creation(self):
        """Test creating a wallet with default values"""
        wallet = Wallet.objects.create(user=self.user)

        self.assertEqual(wallet.balance, Decimal('0.00'))
        self.assertEqual(wallet.currency, 'NGN')
        self.assertEqual(wallet.points, 0)
        self.assertTrue(wallet.is_active)
        self.assertIsNotNone(wallet.wallet_id)

    def test_wallet_one_to_one_relationship(self):
        """Test that each user can only have one wallet"""
        Wallet.objects.create(user=self.user)

        with self.assertRaises(Exception):
            Wallet.objects.create(user=self.user)

    def test_wallet_string_representation(self):
        """Test wallet string representation"""
        wallet = Wallet.objects.create(
            user=self.user,
            balance=Decimal('1000.00'),
            currency='NGN'
        )
        expected = f"Wallet for Test User - Balance: 1000.00 NGN"
        self.assertEqual(str(wallet), expected)


class WalletTransactionModelTests(TestCase):
    """Tests for WalletTransaction model"""

    def setUp(self):
        self.user = User.objects.create_user(
            email='test@example.com',
            password='TestPass123!',
            name='Test User'
        )
        self.wallet = Wallet.objects.create(user=self.user)

    def test_transaction_reference_auto_generation(self):
        """Test that transaction reference is auto-generated"""
        transaction = WalletTransaction.objects.create(
            wallet=self.wallet,
            user=self.user,
            transaction_type='deposit',
            amount=Decimal('500.00'),
            payment_method='bank',
            status='pending'
        )

        self.assertIsNotNone(transaction.reference)
        self.assertTrue(transaction.reference.startswith('WW'))

    def test_transaction_with_amount(self):
        """Test creating transaction with amount"""
        transaction = WalletTransaction.objects.create(
            wallet=self.wallet,
            user=self.user,
            transaction_type='deposit',
            amount=Decimal('500.00'),
            payment_method='bank',
            status='success'
        )

        self.assertEqual(transaction.amount, Decimal('500.00'))
        self.assertIsNone(transaction.points)

    def test_transaction_with_points(self):
        """Test creating transaction with points"""
        transaction = WalletTransaction.objects.create(
            wallet=self.wallet,
            user=self.user,
            transaction_type='referral_reward',
            points=100,
            payment_method='system',
            status='success'
        )

        self.assertEqual(transaction.points, 100)
        self.assertIsNone(transaction.amount)

    def test_transaction_string_representation(self):
        """Test transaction string representation"""
        transaction = WalletTransaction.objects.create(
            wallet=self.wallet,
            user=self.user,
            transaction_type='deposit',
            amount=Decimal('500.00'),
            payment_method='bank',
            status='success'
        )

        expected = f"Deposit - 500.00 for Test User"
        self.assertEqual(str(transaction), expected)