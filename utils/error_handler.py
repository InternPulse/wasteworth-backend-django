from rest_framework.views import exception_handler
from rest_framework import status
from rest_framework.response import Response
from rest_framework.serializers import ValidationError
from rest_framework_simplejwt.exceptions import TokenError
from django.core.exceptions import ObjectDoesNotExist
import re


class ErrorCodes:
    # Authentication errors
    INVALID_CREDENTIALS = "INVALID_CREDENTIALS"
    EMAIL_ALREADY_EXISTS = "EMAIL_ALREADY_EXISTS"
    PASSWORD_MISMATCH = "PASSWORD_MISMATCH"
    INVALID_TOKEN = "INVALID_TOKEN"
    TOKEN_REQUIRED = "TOKEN_REQUIRED"

    # Validation errors
    VALIDATION_ERROR = "VALIDATION_ERROR"
    REQUIRED_FIELD = "REQUIRED_FIELD"
    INVALID_EMAIL = "INVALID_EMAIL"
    WEAK_PASSWORD = "WEAK_PASSWORD"

    # General errors
    NOT_FOUND = "NOT_FOUND"
    SERVER_ERROR = "SERVER_ERROR"
    PERMISSION_DENIED = "PERMISSION_DENIED"


ERROR_MESSAGES = {
    ErrorCodes.INVALID_CREDENTIALS: "The email or password you entered is incorrect. Please try again.",
    ErrorCodes.EMAIL_ALREADY_EXISTS: "An account with this email already exists. Try logging in instead.",
    ErrorCodes.PASSWORD_MISMATCH: "The passwords you entered do not match. Please try again.",
    ErrorCodes.INVALID_TOKEN: "Your session has expired. Please log in again.",
    ErrorCodes.TOKEN_REQUIRED: "Authentication token is required for this action.",
    ErrorCodes.VALIDATION_ERROR: "The provided data is invalid. Please check the details below.",
    ErrorCodes.REQUIRED_FIELD: "This field is required.",
    ErrorCodes.INVALID_EMAIL: "Please enter a valid email address.",
    ErrorCodes.WEAK_PASSWORD: "Password does not meet security requirements.",
    ErrorCodes.NOT_FOUND: "The requested resource was not found.",
    ErrorCodes.SERVER_ERROR: "Something went wrong on our end. Please try again later.",
    ErrorCodes.PERMISSION_DENIED: "You don't have permission to perform this action.",
}


def get_error_code_from_message(message):
    """Map common error messages to error codes"""
    message_lower = str(message).lower()

    if "email already exists" in message_lower or "user with this email already exists" in message_lower:
        return ErrorCodes.EMAIL_ALREADY_EXISTS
    elif "passwords don't match" in message_lower or "password mismatch" in message_lower:
        return ErrorCodes.PASSWORD_MISMATCH
    elif "invalid credentials" in message_lower:
        return ErrorCodes.INVALID_CREDENTIALS
    elif "email and password required" in message_lower:
        return ErrorCodes.REQUIRED_FIELD
    elif "this field is required" in message_lower:
        return ErrorCodes.REQUIRED_FIELD
    elif "enter a valid email address" in message_lower or "invalid email" in message_lower:
        return ErrorCodes.INVALID_EMAIL
    elif "ensure this field has at least" in message_lower and "characters" in message_lower:
        return ErrorCodes.WEAK_PASSWORD
    elif "invalid token" in message_lower:
        return ErrorCodes.INVALID_TOKEN
    elif "refresh token required" in message_lower:
        return ErrorCodes.TOKEN_REQUIRED
    else:
        return ErrorCodes.VALIDATION_ERROR


def format_field_errors(errors):
    """Format DRF serializer errors into a more user-friendly structure"""
    if isinstance(errors, dict):
        formatted_errors = {}
        for field, messages in errors.items():
            if isinstance(messages, list):
                formatted_errors[field] = messages
            else:
                formatted_errors[field] = [str(messages)]
        return formatted_errors
    elif isinstance(errors, list):
        return {"non_field_errors": errors}
    else:
        return {"error": [str(errors)]}


def get_user_friendly_message(exc, default_message=None):
    """Get a user-friendly error message based on the exception"""
    if hasattr(exc, 'detail'):
        if isinstance(exc.detail, dict):
            # Get the first error message from field errors
            for field, messages in exc.detail.items():
                if isinstance(messages, list) and messages:
                    error_code = get_error_code_from_message(messages[0])
                    return ERROR_MESSAGES.get(error_code, str(messages[0]))
                else:
                    error_code = get_error_code_from_message(messages)
                    return ERROR_MESSAGES.get(error_code, str(messages))
        elif isinstance(exc.detail, list) and exc.detail:
            error_code = get_error_code_from_message(exc.detail[0])
            return ERROR_MESSAGES.get(error_code, str(exc.detail[0]))
        else:
            error_code = get_error_code_from_message(exc.detail)
            return ERROR_MESSAGES.get(error_code, str(exc.detail))

    return default_message or ERROR_MESSAGES[ErrorCodes.SERVER_ERROR]


def get_error_code(exc):
    """Determine the appropriate error code based on the exception"""
    if isinstance(exc, TokenError):
        return ErrorCodes.INVALID_TOKEN
    elif isinstance(exc, ObjectDoesNotExist):
        return ErrorCodes.NOT_FOUND
    elif hasattr(exc, 'detail'):
        if isinstance(exc.detail, dict):
            # Get error code from the first field error
            for field, messages in exc.detail.items():
                if isinstance(messages, list) and messages:
                    return get_error_code_from_message(messages[0])
                else:
                    return get_error_code_from_message(messages)
        elif isinstance(exc.detail, list) and exc.detail:
            return get_error_code_from_message(exc.detail[0])
        else:
            return get_error_code_from_message(exc.detail)

    return ErrorCodes.SERVER_ERROR


def custom_exception_handler(exc, context):
    """Custom exception handler that formats all errors consistently"""
    response = exception_handler(exc, context)

    if response is not None:
        error_code = get_error_code(exc)
        user_message = get_user_friendly_message(exc)
        field_errors = format_field_errors(response.data)

        custom_response_data = {
            'success': False,
            'error': {
                'code': error_code,
                'message': user_message,
                'details': field_errors
            }
        }

        response.data = custom_response_data

    return response