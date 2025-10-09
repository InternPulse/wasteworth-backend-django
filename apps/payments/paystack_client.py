"""
Paystack API client for payment operations.
"""
import requests
import hashlib
import hmac
from decimal import Decimal
from django.conf import settings
import logging

logger = logging.getLogger(__name__)


class PaystackClient:
    """
    Client for interacting with Paystack API.
    Handles payment initialization, verification, and transfers.
    """

    def __init__(self):
        self.secret_key = settings.PAYSTACK_SECRET_KEY
        self.public_key = settings.PAYSTACK_PUBLIC_KEY
        self.base_url = settings.PAYSTACK_BASE_URL

        self.headers = {
            'Authorization': f'Bearer {self.secret_key}',
            'Content-Type': 'application/json'
        }

    def initialize_payment(self, email, amount, reference, metadata=None, callback_url=None):
        """
        Initialize a payment transaction.

        Args:
            email: Customer email
            amount: Amount in Naira (will be converted to kobo)
            reference: Unique transaction reference
            metadata: Optional metadata dict
            callback_url: Optional callback URL

        Returns:
            dict with authorization_url and access_code, or error
        """
        try:
            url = f'{self.base_url}/transaction/initialize'

            # Ensure amount is a number (Decimal or float)
            if isinstance(amount, str):
                amount = Decimal(amount)

            payload = {
                'email': email,
                'amount': int(Decimal(str(amount)) * 100),  # Convert Naira to kobo
                'reference': reference,
                'metadata': metadata or {},
                'callback_url': callback_url or settings.PAYSTACK_CALLBACK_URL
            }

            response = requests.post(url, json=payload, headers=self.headers, timeout=30)
            response.raise_for_status()

            data = response.json()

            if data['status']:
                return {
                    'success': True,
                    'authorization_url': data['data']['authorization_url'],
                    'access_code': data['data']['access_code'],
                    'reference': data['data']['reference']
                }
            else:
                return {
                    'success': False,
                    'error': data.get('message', 'Payment initialization failed')
                }

        except requests.RequestException as e:
            logger.error(f"Paystack API error (initialize): {str(e)}")
            return {
                'success': False,
                'error': str(e)
            }

    def verify_payment(self, reference):
        """
        Verify a payment transaction.

        Args:
            reference: Transaction reference

        Returns:
            dict with payment details or error
        """
        try:
            url = f'{self.base_url}/transaction/verify/{reference}'

            response = requests.get(url, headers=self.headers, timeout=30)
            response.raise_for_status()

            data = response.json()

            if data['status'] and data['data']['status'] == 'success':
                return {
                    'success': True,
                    'amount': Decimal(data['data']['amount']) / 100,  # Convert from kobo to Naira
                    'currency': data['data']['currency'],
                    'status': data['data']['status'],
                    'reference': data['data']['reference'],
                    'paid_at': data['data']['paid_at'],
                    'channel': data['data']['channel'],
                    'authorization': data['data'].get('authorization', {}),
                    'customer': data['data'].get('customer', {})
                }
            else:
                return {
                    'success': False,
                    'error': 'Payment verification failed or payment not successful'
                }

        except requests.RequestException as e:
            logger.error(f"Paystack API error (verify): {str(e)}")
            return {
                'success': False,
                'error': str(e)
            }

    def create_transfer_recipient(self, account_number, bank_code, account_name):
        """
        Create a transfer recipient.

        Args:
            account_number: Recipient bank account number
            bank_code: Recipient bank code
            account_name: Recipient account name

        Returns:
            dict with recipient_code or error
        """
        try:
            url = f'{self.base_url}/transferrecipient'

            payload = {
                'type': 'nuban',
                'name': account_name,
                'account_number': account_number,
                'bank_code': bank_code,
                'currency': 'NGN'
            }

            response = requests.post(url, json=payload, headers=self.headers, timeout=30)
            response.raise_for_status()

            data = response.json()

            if data['status']:
                return {
                    'success': True,
                    'recipient_code': data['data']['recipient_code'],
                    'details': data['data']
                }
            else:
                return {
                    'success': False,
                    'error': data.get('message', 'Failed to create transfer recipient')
                }

        except requests.RequestException as e:
            logger.error(f"Paystack API error (create recipient): {str(e)}")
            return {
                'success': False,
                'error': str(e)
            }

    def initiate_transfer(self, amount, recipient_code, reason, reference):
        """
        Initiate a transfer to a recipient.

        Args:
            amount: Amount in Naira (will be converted to kobo)
            recipient_code: Recipient code from create_transfer_recipient
            reason: Transfer reason/description
            reference: Unique transfer reference

        Returns:
            dict with transfer details or error
        """
        try:
            url = f'{self.base_url}/transfer'

            # Ensure amount is a number (Decimal or float)
            if isinstance(amount, str):
                amount = Decimal(amount)

            payload = {
                'source': 'balance',
                'amount': int(Decimal(str(amount)) * 100),  # Convert Naira to kobo
                'recipient': recipient_code,
                'reason': reason,
                'reference': reference
            }

            response = requests.post(url, json=payload, headers=self.headers, timeout=30)
            response.raise_for_status()

            data = response.json()

            if data['status']:
                return {
                    'success': True,
                    'transfer_code': data['data']['transfer_code'],
                    'status': data['data']['status'],
                    'reference': data['data']['reference'],
                    'details': data['data']
                }
            else:
                return {
                    'success': False,
                    'error': data.get('message', 'Transfer initiation failed')
                }

        except requests.RequestException as e:
            logger.error(f"Paystack API error (transfer): {str(e)}")
            return {
                'success': False,
                'error': str(e)
            }

    @staticmethod
    def verify_webhook_signature(payload, signature):
        """
        Verify Paystack webhook signature.

        Args:
            payload: Raw request body (bytes)
            signature: X-Paystack-Signature header value

        Returns:
            bool: True if signature is valid
        """
        try:
            secret = settings.PAYSTACK_WEBHOOK_SECRET.encode('utf-8')
            computed_signature = hmac.new(
                secret,
                payload,
                hashlib.sha512
            ).hexdigest()

            return hmac.compare_digest(computed_signature, signature)

        except Exception as e:
            logger.error(f"Webhook signature verification error: {str(e)}")
            return False
