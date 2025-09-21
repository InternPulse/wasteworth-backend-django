from django.test import TestCase
from rest_framework.test import APITestCase
from rest_framework import status
from django.contrib.auth import get_user_model
from django.utils import timezone
from datetime import timedelta
from unittest.mock import patch, MagicMock
from .models import OTP
from .serializers import OTPVerifySerializer, OTPRequestSerializer
from utils.otp import generate_and_send_otp

User = get_user_model()


class OTPModelTestCase(TestCase):
    def setUp(self):
        self.user = User.objects.create_user(
            name='Test User',
            email='test@example.com',
            password='TestPass123!'
        )

    def test_otp_creation(self):
        """Test OTP model creation with required fields"""
        otp = OTP.objects.create(
            user_id=self.user,
            hashed_otp='hashed_test_otp',
            purpose='signup',
            expires_at=timezone.now() + timedelta(minutes=10)
        )
        self.assertEqual(otp.user_id, self.user)
        self.assertEqual(otp.purpose, 'signup')
        self.assertFalse(otp.used)
        self.assertFalse(otp.is_expired())

    def test_otp_expiration(self):
        """Test OTP expiration functionality"""
        # Create expired OTP
        otp = OTP.objects.create(
            user_id=self.user,
            hashed_otp='hashed_test_otp',
            purpose='signup',
            expires_at=timezone.now() - timedelta(minutes=5)
        )
        self.assertTrue(otp.is_expired())

        # Create valid OTP
        otp_valid = OTP.objects.create(
            user_id=self.user,
            hashed_otp='hashed_test_otp',
            purpose='signup',
            expires_at=timezone.now() + timedelta(minutes=10)
        )
        self.assertFalse(otp_valid.is_expired())

    def test_otp_str_representation(self):
        """Test OTP string representation"""
        otp = OTP.objects.create(
            user_id=self.user,
            hashed_otp='hashed_test_otp',
            purpose='signup',
            expires_at=timezone.now() + timedelta(minutes=10)
        )
        self.assertIn('signup', str(otp))
        self.assertIn('Test User', str(otp))
        self.assertIn('Valid', str(otp))

    def test_otp_auto_expiration_on_save(self):
        """Test that OTP automatically sets expiration if not provided"""
        otp = OTP.objects.create(
            user_id=self.user,
            hashed_otp='hashed_test_otp',
            purpose='signup'
        )
        self.assertIsNotNone(otp.expires_at)
        self.assertGreater(otp.expires_at, timezone.now())


class OTPUtilityTestCase(TestCase):
    def setUp(self):
        self.user = User.objects.create_user(
            name='Test User',
            email='test@example.com',
            password='TestPass123!'
        )

    @patch('utils.otp.send_mail')
    def test_generate_and_send_otp(self, mock_send_mail):
        """Test OTP generation and sending functionality"""
        mock_send_mail.return_value = True

        otp_instance = generate_and_send_otp(self.user, 'signup')

        # Verify OTP was created
        self.assertIsNotNone(otp_instance)
        self.assertEqual(otp_instance.user_id, self.user)
        self.assertEqual(otp_instance.purpose, 'signup')
        self.assertFalse(otp_instance.used)
        self.assertIsNotNone(otp_instance.hashed_otp)

        # Verify email was sent
        mock_send_mail.assert_called_once()
        args, kwargs = mock_send_mail.call_args
        self.assertIn('Your OTP for Signup', kwargs['subject'])
        self.assertEqual(kwargs['recipient_list'], [self.user.email])

    @patch('utils.otp.send_mail')
    def test_generate_and_send_otp_different_purposes(self, mock_send_mail):
        """Test OTP generation for different purposes"""
        mock_send_mail.return_value = True

        purposes = ['signup', 'reset', 'login']
        for purpose in purposes:
            otp_instance = generate_and_send_otp(self.user, purpose)
            self.assertEqual(otp_instance.purpose, purpose)

    @patch('utils.otp.send_mail')
    def test_otp_code_format(self, mock_send_mail):
        """Test that generated OTP is 6 digits"""
        mock_send_mail.return_value = True

        otp_instance = generate_and_send_otp(self.user, 'signup')

        # Check email content contains 6-digit OTP
        args, kwargs = mock_send_mail.call_args
        message = kwargs['message']
        # Extract OTP from message (should be 6 digits)
        import re
        otp_match = re.search(r'Your OTP code is: (\d{6})', message)
        self.assertIsNotNone(otp_match)
        self.assertEqual(len(otp_match.group(1)), 6)


class OTPSerializerTestCase(TestCase):
    def setUp(self):
        self.user = User.objects.create_user(
            name='Test User',
            email='test@example.com',
            password='TestPass123!'
        )

    @patch('utils.otp.send_mail')
    def test_otp_verify_serializer_valid(self, mock_send_mail):
        """Test OTP verification serializer with valid data"""
        mock_send_mail.return_value = True

        # Generate OTP
        otp_instance = generate_and_send_otp(self.user, 'signup')

        # Get the plain OTP code for testing
        from django.contrib.auth.hashers import check_password
        test_otp = '123456'
        otp_instance.hashed_otp = 'pbkdf2_sha256$260000$test$hashedvalue'  # Mock hash
        otp_instance.save()

        # Mock check_password to return True for our test OTP
        with patch('django.contrib.auth.hashers.check_password', return_value=True):
            data = {
                'user_id': str(self.user.id),
                'otp': test_otp
            }
            serializer = OTPVerifySerializer(data=data)
            self.assertTrue(serializer.is_valid())
            self.assertEqual(serializer.validated_data['user'], self.user)
            self.assertEqual(serializer.validated_data['otp_obj'], otp_instance)

    def test_otp_verify_serializer_invalid_user(self):
        """Test OTP verification serializer with invalid user"""
        data = {
            'user_id': 'invalid-uuid',
            'otp': '123456'
        }
        serializer = OTPVerifySerializer(data=data)
        self.assertFalse(serializer.is_valid())

    @patch('utils.otp.send_mail')
    def test_otp_verify_serializer_expired_otp(self, mock_send_mail):
        """Test OTP verification serializer with expired OTP"""
        mock_send_mail.return_value = True

        # Create expired OTP
        otp_instance = OTP.objects.create(
            user_id=self.user,
            hashed_otp='hashed_test_otp',
            purpose='signup',
            expires_at=timezone.now() - timedelta(minutes=5)
        )

        data = {
            'user_id': str(self.user.id),
            'otp': '123456'
        }
        serializer = OTPVerifySerializer(data=data)
        self.assertFalse(serializer.is_valid())
        self.assertIn('otp', serializer.errors)

    def test_otp_request_serializer_valid(self):
        """Test OTP request serializer with valid data"""
        data = {
            'email_or_phone': self.user.email,
            'purpose': 'signup'
        }
        serializer = OTPRequestSerializer(data=data)
        self.assertTrue(serializer.is_valid())
        self.assertEqual(serializer.validated_data['user'], self.user)

    def test_otp_request_serializer_nonexistent_user(self):
        """Test OTP request serializer with non-existent user"""
        data = {
            'email_or_phone': 'nonexistent@example.com',
            'purpose': 'signup'
        }
        serializer = OTPRequestSerializer(data=data)
        self.assertFalse(serializer.is_valid())


class OTPViewTestCase(APITestCase):
    def setUp(self):
        self.user = User.objects.create_user(
            name='Test User',
            email='test@example.com',
            password='TestPass123!',
            role='disposer'
        )

    @patch('utils.otp.send_mail')
    def test_send_otp_view(self, mock_send_mail):
        """Test send OTP view endpoint"""
        mock_send_mail.return_value = True

        url = '/api/v1/otp/send/'
        data = {
            'email_or_phone': self.user.email,
            'purpose': 'signup'
        }
        response = self.client.post(url, data, format='json')

        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertTrue(response.data['success'])
        self.assertIn('otp_id', response.data)
        self.assertIn('expires_at', response.data)

    def test_send_otp_view_nonexistent_user(self):
        """Test send OTP view with non-existent user"""
        url = '/api/v1/otp/send/'
        data = {
            'email_or_phone': 'nonexistent@example.com',
            'purpose': 'signup'
        }
        response = self.client.post(url, data, format='json')

        self.assertEqual(response.status_code, status.HTTP_404_NOT_FOUND)
        self.assertFalse(response.data['success'])

    @patch('utils.otp.send_mail')
    def test_verify_otp_view_signup(self, mock_send_mail):
        """Test verify OTP view for signup action"""
        mock_send_mail.return_value = True

        # Generate OTP
        otp_instance = generate_and_send_otp(self.user, 'signup')

        # Mock successful OTP verification
        with patch('django.contrib.auth.hashers.check_password', return_value=True):
            url = '/api/v1/otp/verify/?action=signup'
            data = {
                'email_or_phone': self.user.email,
                'otp': '123456'
            }
            response = self.client.post(url, data, format='json')

            self.assertEqual(response.status_code, status.HTTP_200_OK)
            self.assertTrue(response.data['success'])
            self.assertIn('tokens', response.data)
            self.assertIn('user', response.data)

    @patch('utils.otp.send_mail')
    def test_verify_otp_view_reset(self, mock_send_mail):
        """Test verify OTP view for password reset action"""
        mock_send_mail.return_value = True

        # Generate OTP
        otp_instance = generate_and_send_otp(self.user, 'reset')

        # Mock successful OTP verification
        with patch('django.contrib.auth.hashers.check_password', return_value=True):
            url = '/api/v1/otp/verify/?action=reset'
            data = {
                'email_or_phone': self.user.email,
                'otp': '123456',
                'new_password': 'NewPassword123!'
            }
            response = self.client.post(url, data, format='json')

            self.assertEqual(response.status_code, status.HTTP_200_OK)
            self.assertTrue(response.data['success'])
            self.assertIn('user', response.data)

    def test_verify_otp_view_invalid_action(self):
        """Test verify OTP view with invalid action"""
        url = '/api/v1/otp/verify/?action=invalid'
        data = {
            'email_or_phone': self.user.email,
            'otp': '123456'
        }
        response = self.client.post(url, data, format='json')

        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertFalse(response.data['success'])

    def test_verify_otp_view_missing_action(self):
        """Test verify OTP view with missing action parameter"""
        url = '/api/v1/otp/verify/'
        data = {
            'email_or_phone': self.user.email,
            'otp': '123456'
        }
        response = self.client.post(url, data, format='json')

        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertFalse(response.data['success'])

    @patch('utils.otp.send_mail')
    def test_verify_otp_view_purpose_mismatch(self, mock_send_mail):
        """Test verify OTP view with purpose mismatch"""
        mock_send_mail.return_value = True

        # Generate OTP for signup but try to use for reset
        otp_instance = generate_and_send_otp(self.user, 'signup')

        # Mock successful OTP verification
        with patch('django.contrib.auth.hashers.check_password', return_value=True):
            url = '/api/v1/otp/verify/?action=reset'
            data = {
                'email_or_phone': self.user.email,
                'otp': '123456'
            }
            response = self.client.post(url, data, format='json')

            self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
            self.assertFalse(response.data['success'])

    @patch('utils.otp.send_mail')
    def test_resend_otp_view(self, mock_send_mail):
        """Test resend OTP view endpoint"""
        mock_send_mail.return_value = True

        # Create initial OTP
        generate_and_send_otp(self.user, 'signup')

        url = '/api/v1/otp/resend/'
        data = {
            'email_or_phone': self.user.email,
            'purpose': 'signup'
        }
        response = self.client.post(url, data, format='json')

        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertTrue(response.data['success'])
        self.assertIn('otp_id', response.data)

    @patch('utils.otp.send_mail')
    def test_request_password_reset_view(self, mock_send_mail):
        """Test request password reset view endpoint"""
        mock_send_mail.return_value = True

        url = '/api/v1/otp/request-password-reset/'
        data = {
            'email_or_phone': self.user.email
        }
        response = self.client.post(url, data, format='json')

        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertTrue(response.data['success'])

    def test_request_password_reset_view_missing_email(self):
        """Test request password reset view with missing email"""
        url = '/api/v1/otp/request-password-reset/'
        data = {}
        response = self.client.post(url, data, format='json')

        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertFalse(response.data['success'])


class OTPSecurityTestCase(APITestCase):
    def setUp(self):
        self.user = User.objects.create_user(
            name='Test User',
            email='test@example.com',
            password='TestPass123!'
        )

    @patch('utils.otp.send_mail')
    def test_otp_single_use(self, mock_send_mail):
        """Test that OTP can only be used once"""
        mock_send_mail.return_value = True

        # Generate OTP
        otp_instance = generate_and_send_otp(self.user, 'signup')

        # Mock successful OTP verification
        with patch('django.contrib.auth.hashers.check_password', return_value=True):
            url = '/api/v1/otp/verify/?action=signup'
            data = {
                'email_or_phone': self.user.email,
                'otp': '123456'
            }

            # First use should succeed
            response = self.client.post(url, data, format='json')
            self.assertEqual(response.status_code, status.HTTP_200_OK)

            # Second use should fail
            response = self.client.post(url, data, format='json')
            self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)

    @patch('utils.otp.send_mail')
    def test_otp_invalidates_previous(self, mock_send_mail):
        """Test that generating new OTP invalidates previous ones"""
        mock_send_mail.return_value = True

        # Generate first OTP
        otp1 = generate_and_send_otp(self.user, 'signup')

        # Generate second OTP (should invalidate first)
        url = '/api/v1/otp/resend/'
        data = {
            'email_or_phone': self.user.email,
            'purpose': 'signup'
        }
        response = self.client.post(url, data, format='json')
        self.assertEqual(response.status_code, status.HTTP_200_OK)

        # Verify first OTP is now marked as used
        otp1.refresh_from_db()
        self.assertTrue(otp1.used)

    def test_otp_rate_limiting_prevention(self):
        """Test that we can't spam OTP requests (basic check)"""
        # This is a basic test - in production you'd want actual rate limiting
        url = '/api/v1/otp/send/'
        data = {
            'email_or_phone': 'nonexistent@example.com',
            'purpose': 'signup'
        }

        # Multiple requests should not cause server errors
        for _ in range(5):
            response = self.client.post(url, data, format='json')
            self.assertIn(response.status_code, [400, 404, 429])  # Various acceptable error codes

    @patch('utils.otp.send_mail')
    def test_otp_email_phone_detection(self, mock_send_mail):
        """Test that system correctly detects email vs phone"""
        mock_send_mail.return_value = True

        # Test with email
        url = '/api/v1/otp/send/'
        data = {
            'email_or_phone': self.user.email,
            'purpose': 'signup'
        }
        response = self.client.post(url, data, format='json')
        self.assertEqual(response.status_code, status.HTTP_200_OK)

        # Test with phone format (if user had phone)
        user_with_phone = User.objects.create_user(
            name='Phone User',
            email='phone@example.com',
            phone='+1234567890',
            password='TestPass123!'
        )

        data = {
            'email_or_phone': '+1234567890',
            'purpose': 'signup'
        }
        response = self.client.post(url, data, format='json')
        self.assertEqual(response.status_code, status.HTTP_200_OK)