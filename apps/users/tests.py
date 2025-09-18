from django.test import TestCase
from rest_framework.test import APITestCase
from rest_framework import status
from django.urls import reverse
from django.contrib.auth import get_user_model
from rest_framework_simplejwt.tokens import RefreshToken
import json

User = get_user_model()


class UserSignupTestCase(APITestCase):
    def setUp(self):
        self.signup_url = '/api/v1/users/signup/'
        self.valid_signup_data = {
            'name': 'Test User',
            'email': 'test@example.com',
            'password': 'StrongPass123#',
            'confirm_password': 'StrongPass123#',
            'role': 'disposer'
        }

    def test_valid_signup(self):
        response = self.client.post(self.signup_url, self.valid_signup_data, format='json')
        self.assertEqual(response.status_code, status.HTTP_201_CREATED)
        self.assertIn('success', response.data)
        self.assertIn('message', response.data)
        self.assertIn('user', response.data)
        self.assertIn('tokens', response.data)
        self.assertTrue(response.data['success'])
        self.assertEqual(response.data['message'], 'User created successfully')

        # Verify user was created in database
        user = User.objects.get(email='test@example.com')
        self.assertEqual(user.email, 'test@example.com')
        self.assertEqual(user.name, 'Test User')
        self.assertEqual(user.role, 'disposer')  # default role
        self.assertTrue(user.check_password('StrongPass123#'))

    def test_signup_password_mismatch(self):
        data = self.valid_signup_data.copy()
        data['confirm_password'] = 'differentpassword'
        response = self.client.post(self.signup_url, data, format='json')
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        # Our implementation puts password mismatch error in confirm_password field
        self.assertTrue('confirm_password' in response.data or 'non_field_errors' in response.data)

    def test_signup_duplicate_email(self):
        # Create a user first
        User.objects.create_user(
            email='test@example.com',
            password='password123'
        )

        response = self.client.post(self.signup_url, self.valid_signup_data, format='json')
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertIn('email', response.data)

    def test_signup_invalid_email(self):
        data = self.valid_signup_data.copy()
        data['email'] = 'invalid-email'
        response = self.client.post(self.signup_url, data, format='json')
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
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
        self.assertIn('password', response.data)

    def test_signup_weak_password_detailed_validation(self):
        """Test our enhanced password validation with detailed feedback"""
        data = self.valid_signup_data.copy()
        data['password'] = 'weakpass'
        data['confirm_password'] = 'weakpass'
        response = self.client.post(self.signup_url, data, format='json')
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
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
        self.assertIn('password', response.data)

    def test_login_empty_fields(self):
        data = {'email': '', 'password': ''}
        response = self.client.post(self.login_url, data, format='json')
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
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
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertIn('error', response.data)

    def test_logout_invalid_refresh_token(self):
        # Authenticate with access token
        self.client.credentials(HTTP_AUTHORIZATION='Bearer ' + self.access_token)

        data = {'refresh_token': 'invalid-token'}
        response = self.client.post(self.logout_url, data, format='json')
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
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
            'confirm_password': 'weak',
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
