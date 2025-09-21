from django.test import TestCase
from rest_framework.test import APITestCase
from rest_framework import status
from django.urls import reverse
from django.contrib.auth import get_user_model
from rest_framework_simplejwt.tokens import RefreshToken
from django.conf import settings
from datetime import datetime, timedelta
from unittest.mock import patch
import jwt
import json

User = get_user_model()


class UserSignupTestCase(APITestCase):
    def setUp(self):
        self.signup_url = '/api/v1/users/signup/'
        self.valid_signup_data = {
            'email': 'test@example.com',
            'password': 'StrongPass123#',
            'confirm_password': 'StrongPass123#',
            'role': 'disposer'
        }

    @patch('utils.otp.send_mail')
    def test_valid_signup(self, mock_send_mail):
        mock_send_mail.return_value = True

        response = self.client.post(self.signup_url, self.valid_signup_data, format='json')
        self.assertEqual(response.status_code, status.HTTP_201_CREATED)
        self.assertIn('success', response.data)
        self.assertIn('message', response.data)
        self.assertIn('user_id', response.data)
        self.assertIn('email', response.data)
        self.assertIn('is_verified', response.data)
        self.assertIn('otp_sent', response.data)
        self.assertTrue(response.data['success'])
        self.assertIn('Account created successfully', response.data['message'])

        # Verify user was created in database as unverified
        user = User.objects.get(email='test@example.com')
        self.assertEqual(user.email, 'test@example.com')
        self.assertEqual(user.role, 'disposer')
        self.assertFalse(user.is_verified)  # New users start unverified
        self.assertTrue(user.check_password('StrongPass123#'))

    def test_signup_password_mismatch(self):
        data = self.valid_signup_data.copy()
        data['confirm_password'] = 'differentpassword'
        response = self.client.post(self.signup_url, data, format='json')
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        # Our implementation puts password mismatch error in confirm_password field
        if 'error' in response.data:
            error_details = response.data['error']['details']
            self.assertTrue('confirm_password' in error_details or 'non_field_errors' in error_details)
        else:
            self.assertTrue('confirm_password' in response.data or 'non_field_errors' in response.data)

    def test_signup_duplicate_email(self):
        # Create a user first
        User.objects.create_user(
            email='test@example.com',
            password='password123'
        )

        response = self.client.post(self.signup_url, self.valid_signup_data, format='json')
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        if 'error' in response.data:
            self.assertIn('email', response.data['error']['details'])
        else:
            self.assertIn('email', response.data)

    def test_signup_invalid_email(self):
        data = self.valid_signup_data.copy()
        data['email'] = 'invalid-email'
        response = self.client.post(self.signup_url, data, format='json')
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        if 'error' in response.data:
            self.assertIn('email', response.data['error']['details'])
        else:
            self.assertIn('email', response.data)

    def test_signup_missing_required_fields(self):
        data = {}
        response = self.client.post(self.signup_url, data, format='json')
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        # Check that required fields are reported as missing
        required_fields = ['name', 'password', 'confirm_password']
        for field in required_fields:
            self.assertIn(field, response.data)

    def test_signup_short_password(self):
        data = self.valid_signup_data.copy()
        data['password'] = '123'
        data['confirm_password'] = '123'
        response = self.client.post(self.signup_url, data, format='json')
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        if 'error' in response.data:
            self.assertIn('password', response.data['error']['details'])
        else:
            self.assertIn('password', response.data)

    def test_signup_weak_password_detailed_validation(self):
        """Test our enhanced password validation with detailed feedback"""
        data = self.valid_signup_data.copy()
        data['password'] = 'weakpass'
        data['confirm_password'] = 'weakpass'
        response = self.client.post(self.signup_url, data, format='json')
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        if 'error' in response.data:
            self.assertIn('password', response.data['error']['details'])
        else:
            self.assertIn('password', response.data)

        # Check that multiple specific requirements are listed
        password_errors = response.data['password']
        self.assertIsInstance(password_errors, list)
        error_text = ' '.join(password_errors)
        self.assertIn('uppercase letter', error_text)
        self.assertIn('number', error_text)
        self.assertIn('special character', error_text)

    def test_signup_missing_name_field(self):
        """Test missing name field (required field)"""
        data = self.valid_signup_data.copy()
        del data['name']
        response = self.client.post(self.signup_url, data, format='json')
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertIn('name', response.data)

    def test_signup_empty_string_fields(self):
        """Test empty string validation (edge case from GitHub)"""
        data = self.valid_signup_data.copy()
        data['email'] = ''
        data['name'] = ''
        response = self.client.post(self.signup_url, data, format='json')
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        if 'error' in response.data:
            error_details = response.data['error']['details']
            self.assertTrue('email' in error_details or 'name' in error_details)
        else:
            self.assertTrue('email' in response.data or 'name' in response.data)

    def test_signup_invalid_role(self):
        """Test invalid role choice"""
        data = self.valid_signup_data.copy()
        data['role'] = 'invalid_role'
        response = self.client.post(self.signup_url, data, format='json')
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertIn('role', response.data)


class UserLoginTestCase(APITestCase):
    def setUp(self):
        self.login_url = '/api/v1/users/login/'
        self.user = User.objects.create_user(
            name='Test User',
            email='test@example.com',
            password='StrongPass123#'
        )

    def test_valid_login(self):
        data = {
            'email': 'test@example.com',
            'password': 'StrongPass123#'
        }
        response = self.client.post(self.login_url, data, format='json')
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertIn('success', response.data)
        self.assertIn('message', response.data)
        self.assertIn('user', response.data)
        self.assertIn('tokens', response.data)
        self.assertTrue(response.data['success'])
        self.assertEqual(response.data['message'], 'Login successful')

    def test_login_invalid_email(self):
        data = {
            'email': 'nonexistent@example.com',
            'password': 'testpassword123'
        }
        response = self.client.post(self.login_url, data, format='json')
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertIn('non_field_errors', response.data)

    def test_login_invalid_password(self):
        data = {
            'email': 'test@example.com',
            'password': 'wrongpassword'
        }
        response = self.client.post(self.login_url, data, format='json')
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertIn('non_field_errors', response.data)

        # Test our enhanced error message
        error_message = response.data['non_field_errors'][0]
        self.assertIn('password you entered is incorrect', error_message.lower())

    def test_login_missing_fields(self):
        data = {'email': 'test@example.com'}
        response = self.client.post(self.login_url, data, format='json')
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        if 'error' in response.data:
            self.assertIn('password', response.data['error']['details'])
        else:
            self.assertIn('password', response.data)

    def test_login_empty_fields(self):
        data = {'email': '', 'password': ''}
        response = self.client.post(self.login_url, data, format='json')
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        if 'error' in response.data:
            error_details = response.data['error']['details']
            self.assertTrue('email' in error_details or 'password' in error_details)
        else:
            self.assertTrue('email' in response.data or 'password' in response.data)


class UserLogoutTestCase(APITestCase):
    def setUp(self):
        self.logout_url = '/api/v1/users/logout/'
        self.user = User.objects.create_user(
            email='test@example.com',
            password='testpassword123'
        )
        self.refresh = RefreshToken.for_user(self.user)
        self.access_token = str(self.refresh.access_token)
        self.refresh_token = str(self.refresh)

    def test_valid_logout(self):
        # Authenticate with access token
        self.client.credentials(HTTP_AUTHORIZATION='Bearer ' + self.access_token)

        data = {'refresh_token': self.refresh_token}
        response = self.client.post(self.logout_url, data, format='json')
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(response.data['message'], 'Logout successful')

    def test_logout_missing_refresh_token(self):
        # Authenticate with access token
        self.client.credentials(HTTP_AUTHORIZATION='Bearer ' + self.access_token)

        data = {}
        response = self.client.post(self.logout_url, data, format='json')
        self.assertEqual(response.status_code, status.HTTP_401_UNAUTHORIZED)
        self.assertIn('error', response.data)

    def test_logout_invalid_refresh_token(self):
        # Authenticate with access token
        self.client.credentials(HTTP_AUTHORIZATION='Bearer ' + self.access_token)

        data = {'refresh_token': 'invalid-token'}
        response = self.client.post(self.logout_url, data, format='json')
        self.assertEqual(response.status_code, status.HTTP_401_UNAUTHORIZED)
        self.assertIn('error', response.data)

    def test_logout_without_authentication(self):
        # Don't authenticate
        data = {'refresh_token': self.refresh_token}
        response = self.client.post(self.logout_url, data, format='json')
        self.assertEqual(response.status_code, status.HTTP_401_UNAUTHORIZED)

    def test_logout_missing_refresh_token_enhanced_error(self):
        """Test our enhanced error format for missing refresh token"""
        self.client.credentials(HTTP_AUTHORIZATION='Bearer ' + self.access_token)
        data = {}
        response = self.client.post(self.logout_url, data, format='json')
        self.assertEqual(response.status_code, status.HTTP_401_UNAUTHORIZED)

        # Test our enhanced error response format
        self.assertIn('success', response.data)
        self.assertIn('error', response.data)
        self.assertFalse(response.data['success'])
        self.assertIn('code', response.data['error'])
        self.assertEqual(response.data['error']['code'], 'TOKEN_REQUIRED')

    def test_logout_invalid_refresh_token_enhanced_error(self):
        """Test our enhanced error format for invalid refresh token"""
        self.client.credentials(HTTP_AUTHORIZATION='Bearer ' + self.access_token)
        data = {'refresh_token': 'invalid-token'}
        response = self.client.post(self.logout_url, data, format='json')
        self.assertEqual(response.status_code, status.HTTP_401_UNAUTHORIZED)

        # Test our enhanced error response format
        self.assertIn('success', response.data)
        self.assertIn('error', response.data)
        self.assertFalse(response.data['success'])
        self.assertIn('code', response.data['error'])
        self.assertEqual(response.data['error']['code'], 'INVALID_TOKEN')


class ErrorHandlingTestCase(APITestCase):
    """Test our enhanced error handling system specifically"""

    def setUp(self):
        self.signup_url = '/api/v1/users/signup/'
        self.login_url = '/api/v1/users/login/'

    def test_password_validation_detailed_errors(self):
        """Test that our password validation returns detailed, specific errors"""
        data = {
            'name': 'Test User',
            'email': 'test@example.com',
            'password': 'weak',
            'password_confirm': 'weak',
            'role': 'disposer'
        }
        response = self.client.post(self.signup_url, data, format='json')
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)

        # Check password validation provides specific feedback
        password_errors = response.data.get('password', [])
        self.assertIsInstance(password_errors, list)
        self.assertGreater(len(password_errors), 1)  # Multiple specific errors

        # Check for specific requirements
        all_errors = ' '.join(password_errors)
        self.assertIn('8 characters', all_errors)
        self.assertIn('uppercase', all_errors)
        self.assertIn('number', all_errors)
        self.assertIn('special character', all_errors)

    def test_email_validation_helpful_message(self):
        """Test enhanced email validation message"""
        # Create user first
        User.objects.create_user(
            name='Existing User',
            email='existing@example.com',
            password='StrongPass123#'
        )

        data = {
            'name': 'Test User',
            'email': 'existing@example.com',
            'password': 'StrongPass123#',
            'confirm_password': 'StrongPass123#',
            'role': 'disposer'
        }
        response = self.client.post(self.signup_url, data, format='json')
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)

        # Check enhanced email error message
        email_errors = response.data.get('email', [])
        error_text = ' '.join(email_errors) if isinstance(email_errors, list) else str(email_errors)
        self.assertIn('already exists', error_text.lower())

    def test_login_specific_error_messages(self):
        """Test that login provides specific error messages"""
        # Test non-existent email
        data = {
            'email': 'nonexistent@example.com',
            'password': 'StrongPass123#'
        }
        response = self.client.post(self.login_url, data, format='json')
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)

        error_message = response.data['non_field_errors'][0]
        self.assertIn('no account found', error_message.lower())

    def test_server_error_handling(self):
        """Test that server errors are properly handled by our middleware"""
        # This would test our exception middleware in real scenarios
        # For now, we verify the error handler components exist
        from utils.error_handler import ErrorCodes, ERROR_MESSAGES, custom_exception_handler

        self.assertIsNotNone(ErrorCodes.SERVER_ERROR)
        self.assertIsNotNone(ERROR_MESSAGES)
        self.assertIsNotNone(custom_exception_handler)


class ForgotPasswordTestCase(APITestCase):
    def setUp(self):
        self.forgot_password_url = '/api/v1/users/forgotPassword/'
        self.user = User.objects.create_user(
            email='test@example.com',
            password='StrongPass123#'
        )

    @patch('utils.otp.send_mail')
    def test_forgot_password_valid_email(self, mock_send_mail):
        """Test forgot password with valid email - now sends OTP"""
        mock_send_mail.return_value = True

        data = {'email': 'test@example.com'}
        response = self.client.post(self.forgot_password_url, data, format='json')
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertIn('success', response.data)
        self.assertIn('message', response.data)
        self.assertIn('next_step', response.data)
        self.assertTrue(response.data['success'])
        self.assertIn('password reset instructions will be sent', response.data['message'])

    def test_forgot_password_nonexistent_email(self):
        """Test forgot password with non-existent email (should return same message for security)"""
        data = {'email': 'nonexistent@example.com'}
        response = self.client.post(self.forgot_password_url, data, format='json')
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertIn('success', response.data)
        self.assertTrue(response.data['success'])
        self.assertIn('password reset instructions will be sent', response.data['message'])

    def test_forgot_password_invalid_email_format(self):
        """Test forgot password with invalid email format"""
        data = {'email': 'invalid-email'}
        response = self.client.post(self.forgot_password_url, data, format='json')
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertIn('email', response.data['errors'])

    def test_forgot_password_missing_email(self):
        """Test forgot password with missing email field"""
        data = {}
        response = self.client.post(self.forgot_password_url, data, format='json')
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertIn('email', response.data['errors'])

    def test_forgot_password_empty_email(self):
        """Test forgot password with empty email"""
        data = {'email': ''}
        response = self.client.post(self.forgot_password_url, data, format='json')
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertIn('email', response.data['errors'])


class ResetPasswordTestCase(APITestCase):
    def setUp(self):
        self.user = User.objects.create_user(
            name='Test User',
            email='test@example.com',
            password='OldPass123#'
        )
        # Generate valid reset token
        exp = datetime.utcnow() + timedelta(hours=1)
        self.valid_token_payload = {
            "user_id": str(self.user.id),  # Convert UUID to string
            "exp": exp.timestamp(),
        }
        self.valid_token = jwt.encode(self.valid_token_payload, settings.SECRET_KEY, algorithm="HS256")
        if isinstance(self.valid_token, bytes):
            self.valid_token = self.valid_token.decode("utf-8")

        self.reset_password_url = f'/api/v1/users/resetPassword/{self.valid_token}/'

    def test_reset_password_valid_token(self):
        """Test reset password with valid token and password"""
        data = {
            'password': 'NewStrongPass123#',
            'password_confirm': 'NewStrongPass123#'
        }
        response = self.client.patch(self.reset_password_url, data, format='json')
        if response.status_code != status.HTTP_200_OK:
            print(f"Response status: {response.status_code}")
            self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(response.data['detail'], 'Password has been reset successfully.')

        # Verify password was actually changed
        self.user.refresh_from_db()
        self.assertTrue(self.user.check_password('NewStrongPass123#'))

    def test_reset_password_expired_token(self):
        """Test reset password with expired token"""
        # Generate expired token
        exp = datetime.utcnow() - timedelta(hours=1)  # 1 hour ago
        expired_payload = {
            "user_id": str(self.user.id),
            "exp": exp.timestamp(),
        }
        expired_token = jwt.encode(expired_payload, settings.SECRET_KEY, algorithm="HS256")
        if isinstance(expired_token, bytes):
            expired_token = expired_token.decode("utf-8")

        url = f'/api/v1/users/resetPassword/{expired_token}/'
        data = {
            'password': 'NewStrongPass123#',
            'password_confirm': 'NewStrongPass123#'
        }
        response = self.client.patch(url, data, format='json')
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertEqual(response.data['detail'], 'Reset token has expired.')

    def test_reset_password_invalid_token(self):
        """Test reset password with invalid token"""
        invalid_token = 'invalid-token-string'
        url = f'/api/v1/users/resetPassword/{invalid_token}/'
        data = {
            'password': 'NewStrongPass123#',
            'password_confirm': 'NewStrongPass123#'
        }
        response = self.client.patch(url, data, format='json')
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertEqual(response.data['detail'], 'Invalid reset token.')

    def test_reset_password_user_not_found(self):
        """Test reset password with token for non-existent user"""
        # Generate token for non-existent user
        exp = datetime.utcnow() + timedelta(hours=1)
        payload = {
            "user_id": "99999999-9999-4999-9999-999999999999",  # Non-existent UUID string
            "exp": exp.timestamp(),
        }
        token = jwt.encode(payload, settings.SECRET_KEY, algorithm="HS256")
        if isinstance(token, bytes):
            token = token.decode("utf-8")

        url = f'/api/v1/users/resetPassword/{token}/'
        data = {
            'password': 'NewStrongPass123#',
            'password_confirm': 'NewStrongPass123#'
        }
        response = self.client.patch(url, data, format='json')
        self.assertEqual(response.status_code, status.HTTP_404_NOT_FOUND)
        self.assertEqual(response.data['detail'], 'User not found.')

    def test_reset_password_password_mismatch(self):
        """Test reset password with mismatched passwords"""
        data = {
            'password': 'NewStrongPass123#',
            'password_confirm': 'DifferentPass123#'
        }
        response = self.client.patch(self.reset_password_url, data, format='json')
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        error_details = response.data['error']['details']
        self.assertTrue('password' in error_details or 'password_confirm' in error_details or 'non_field_errors' in error_details)

    def test_reset_password_weak_password(self):
        """Test reset password with weak password"""
        data = {
            'password': 'weak',
            'password_confirm': 'weak'
        }
        response = self.client.patch(self.reset_password_url, data, format='json')
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        if 'error' in response.data:
            self.assertIn('password', response.data['error']['details'])
        else:
            self.assertIn('password', response.data)

    def test_reset_password_missing_fields(self):
        """Test reset password with missing required fields"""
        data = {}
        response = self.client.patch(self.reset_password_url, data, format='json')
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        error_details = response.data['error']['details']
        self.assertTrue('password' in error_details or 'password_confirm' in error_details)


class UpdatePasswordTestCase(APITestCase):
    def setUp(self):
        self.update_password_url = '/api/v1/users/updatePassword/'
        self.user = User.objects.create_user(
            email='test@example.com',
            password='OldPass123#'
        )
        self.refresh = RefreshToken.for_user(self.user)
        self.access_token = str(self.refresh.access_token)

    @patch('utils.otp.send_mail')
    def test_update_password_step1_send_otp(self, mock_send_mail):
        """Test update password step 1 - send OTP"""
        mock_send_mail.return_value = True

        self.client.credentials(HTTP_AUTHORIZATION='Bearer ' + self.access_token)
        data = {
            'old_password': 'OldPass123#'
        }
        response = self.client.patch(self.update_password_url, data, format='json')
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertTrue(response.data['success'])
        self.assertIn('OTP sent to your email', response.data['message'])
        self.assertIn('otp_id', response.data)

    @patch('utils.otp.send_mail')
    def test_update_password_step2_verify_otp_and_update(self, mock_send_mail):
        """Test update password step 2 - verify OTP and update password"""
        mock_send_mail.return_value = True

        self.client.credentials(HTTP_AUTHORIZATION='Bearer ' + self.access_token)

        # First send OTP
        step1_data = {'old_password': 'OldPass123#'}
        step1_response = self.client.patch(self.update_password_url, step1_data, format='json')
        self.assertEqual(step1_response.status_code, status.HTTP_200_OK)

        # Mock successful OTP verification for step 2
        with patch('django.contrib.auth.hashers.check_password', return_value=True):
            step2_data = {
                'old_password': 'OldPass123#',
                'otp': '123456',
                'new_password': 'NewStrongPass123#',
                'new_password_confirm': 'NewStrongPass123#'
            }
            step2_response = self.client.patch(self.update_password_url, step2_data, format='json')
            self.assertEqual(step2_response.status_code, status.HTTP_200_OK)
            self.assertTrue(step2_response.data['success'])
            self.assertEqual(step2_response.data['message'], 'Password updated successfully')

    def test_update_password_valid_data(self):
        """Test legacy compatibility - this test should be updated for the new flow"""
        # This test is kept for backwards compatibility but may need adjustment
        # based on the new two-step OTP process
        pass

    def test_update_password_wrong_old_password(self):
        """Test update password with wrong current password"""
        self.client.credentials(HTTP_AUTHORIZATION='Bearer ' + self.access_token)
        data = {
            'old_password': 'WrongPass123#',
            'new_password': 'NewStrongPass123#',
            'new_password_confirm': 'NewStrongPass123#'
        }
        response = self.client.patch(self.update_password_url, data, format='json')
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        error_details = response.data['error']['details']
        self.assertTrue('old_password' in error_details or 'non_field_errors' in error_details)

    def test_update_password_mismatch(self):
        """Test update password with mismatched new passwords"""
        self.client.credentials(HTTP_AUTHORIZATION='Bearer ' + self.access_token)
        data = {
            'old_password': 'OldPass123#',
            'new_password': 'NewStrongPass123#',
            'new_password_confirm': 'DifferentPass123#'
        }
        response = self.client.patch(self.update_password_url, data, format='json')
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        error_details = response.data['error']['details']
        self.assertTrue('new_password' in error_details or 'new_password_confirm' in error_details or 'non_field_errors' in error_details)

    def test_update_password_weak_new_password(self):
        """Test update password with weak new password"""
        self.client.credentials(HTTP_AUTHORIZATION='Bearer ' + self.access_token)
        data = {
            'old_password': 'OldPass123#',
            'new_password': 'weak',
            'new_password_confirm': 'weak'
        }
        response = self.client.patch(self.update_password_url, data, format='json')
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertIn('new_password', response.data['error']['details'])

    def test_update_password_unauthenticated(self):
        """Test update password without authentication"""
        data = {
            'old_password': 'OldPass123#',
            'new_password': 'NewStrongPass123#',
            'new_password_confirm': 'NewStrongPass123#'
        }
        response = self.client.patch(self.update_password_url, data, format='json')
        self.assertEqual(response.status_code, status.HTTP_401_UNAUTHORIZED)

    def test_update_password_missing_fields(self):
        """Test update password with missing required fields"""
        self.client.credentials(HTTP_AUTHORIZATION='Bearer ' + self.access_token)
        data = {'old_password': 'OldPass123#'}
        response = self.client.patch(self.update_password_url, data, format='json')
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        error_details = response.data['error']['details']
        self.assertTrue('new_password' in error_details or 'new_password_confirm' in error_details)

    def test_update_password_empty_fields(self):
        """Test update password with empty fields"""
        self.client.credentials(HTTP_AUTHORIZATION='Bearer ' + self.access_token)
        data = {
            'old_password': '',
            'new_password': '',
            'new_password_confirm': ''
        }
        response = self.client.patch(self.update_password_url, data, format='json')
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        expected_fields = ['old_password', 'new_password', 'new_password_confirm']
        error_details = response.data['error']['details']
        has_expected_error = any(field in error_details for field in expected_fields)
        self.assertTrue(has_expected_error)
