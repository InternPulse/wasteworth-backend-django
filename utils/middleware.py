import logging
import json
from django.http import JsonResponse
from django.conf import settings
from django.core.exceptions import PermissionDenied, ValidationError
from django.db import DatabaseError
from .error_handler import ErrorCodes, ERROR_MESSAGES

logger = logging.getLogger(__name__)


class ExceptionMiddleware:
    """
    Middleware to catch unhandled exceptions and return consistent JSON error responses
    for API endpoints. This ensures all errors follow the same format.
    """

    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        response = self.get_response(request)
        return response

    def process_exception(self, request, exception):
        """
        Process any unhandled exceptions that occur during request processing.
        Only handles API requests to avoid interfering with admin/static file serving.
        """

        # Only handle API requests (adjust path prefix as needed)
        if not self._is_api_request(request):
            return None

        # Log the exception for debugging
        logger.error(
            f"Unhandled exception in {request.method} {request.path}: {str(exception)}",
            exc_info=True,
            extra={
                'request_method': request.method,
                'request_path': request.path,
                'user_id': getattr(request.user, 'id', None) if hasattr(request, 'user') else None,
            }
        )

        # Determine error code and message based on exception type
        error_response = self._get_error_response(exception)

        return JsonResponse(error_response['data'], status=error_response['status'])

    def _is_api_request(self, request):
        """
        Determine if this is an API request that should return JSON errors.
        Customize this logic based on your URL patterns.
        """
        api_prefixes = ['/api/', '/auth/']
        return any(request.path.startswith(prefix) for prefix in api_prefixes)

    def _get_error_response(self, exception):
        """
        Map different exception types to appropriate error responses.
        """

        if isinstance(exception, PermissionDenied):
            return {
                'data': {
                    'success': False,
                    'error': {
                        'code': ErrorCodes.PERMISSION_DENIED,
                        'message': ERROR_MESSAGES[ErrorCodes.PERMISSION_DENIED],
                        'details': {'error': ['You do not have permission to access this resource.']}
                    }
                },
                'status': 403
            }

        elif isinstance(exception, ValidationError):
            return {
                'data': {
                    'success': False,
                    'error': {
                        'code': ErrorCodes.VALIDATION_ERROR,
                        'message': ERROR_MESSAGES[ErrorCodes.VALIDATION_ERROR],
                        'details': {'error': [str(exception)]}
                    }
                },
                'status': 400
            }

        elif isinstance(exception, DatabaseError):
            # Don't expose database details in production
            error_detail = str(exception) if settings.DEBUG else 'Database operation failed'
            return {
                'data': {
                    'success': False,
                    'error': {
                        'code': ErrorCodes.SERVER_ERROR,
                        'message': ERROR_MESSAGES[ErrorCodes.SERVER_ERROR],
                        'details': {'error': [error_detail]}
                    }
                },
                'status': 500
            }

        else:
            # Generic server error for any other unhandled exception
            error_detail = str(exception) if settings.DEBUG else 'An unexpected error occurred'
            return {
                'data': {
                    'success': False,
                    'error': {
                        'code': ErrorCodes.SERVER_ERROR,
                        'message': ERROR_MESSAGES[ErrorCodes.SERVER_ERROR],
                        'details': {'error': [error_detail]}
                    }
                },
                'status': 500
            }

    def process_response(self, request, response):
        """
        Process responses to handle common HTTP error status codes
        and convert them to consistent JSON format for API requests.
        """

        if not self._is_api_request(request):
            return response

        # Handle 404 errors
        if response.status_code == 404:
            return JsonResponse({
                'success': False,
                'error': {
                    'code': ErrorCodes.NOT_FOUND,
                    'message': ERROR_MESSAGES[ErrorCodes.NOT_FOUND],
                    'details': {'error': ['The requested resource was not found.']}
                }
            }, status=404)

        # Handle 403 errors
        if response.status_code == 403:
            return JsonResponse({
                'success': False,
                'error': {
                    'code': ErrorCodes.PERMISSION_DENIED,
                    'message': ERROR_MESSAGES[ErrorCodes.PERMISSION_DENIED],
                    'details': {'error': ['You do not have permission to access this resource.']}
                }
            }, status=403)

        return response