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
        self.signup_url = '/api/users/signup/'
        self.valid_signup_data = {
            'email': 'test@example.com',
            'password': 'testpassword123',
            'confirm_password': 'testpassword123'
        }

    def test_valid_signup(self):
        response = self.client.post(self.signup_url, self.valid_signup_data, format='json')
        self.assertEqual(response.status_code, status.HTTP_201_CREATED)
        self.assertIn('message', response.data)
        self.assertIn('user', response.data)
        self.assertIn('tokens', response.data)
        self.assertEqual(response.data['message'], 'User created successfully')

        # Verify user was created in database
        user = User.objects.get(email='test@example.com')
        self.assertEqual(user.email, 'test@example.com')
        self.assertEqual(user.role, 'disposer')  # default role
        self.assertTrue(user.check_password('testpassword123'))

    def test_signup_password_mismatch(self):
        data = self.valid_signup_data.copy()
        data['confirm_password'] = 'differentpassword'
        response = self.client.post(self.signup_url, data, format='json')
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertIn('non_field_errors', response.data)

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
        self.assertIn('email', response.data)
        self.assertIn('password', response.data)
        self.assertIn('confirm_password', response.data)

    def test_signup_short_password(self):
        data = self.valid_signup_data.copy()
        data['password'] = '123'
        data['confirm_password'] = '123'
        response = self.client.post(self.signup_url, data, format='json')
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertIn('password', response.data)


class UserLoginTestCase(APITestCase):
    def setUp(self):
        self.login_url = '/api/users/login/'
        self.user = User.objects.create_user(
            email='test@example.com',
            password='testpassword123'
        )

    def test_valid_login(self):
        data = {
            'email': 'test@example.com',
            'password': 'testpassword123'
        }
        response = self.client.post(self.login_url, data, format='json')
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertIn('message', response.data)
        self.assertIn('user', response.data)
        self.assertIn('tokens', response.data)
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
        self.logout_url = '/api/users/logout/'
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
