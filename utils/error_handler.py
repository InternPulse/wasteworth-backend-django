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

    # OTP-related errors
    OTP_REQUIRED = "OTP_REQUIRED"
    INVALID_OTP = "INVALID_OTP"
    OTP_EXPIRED = "OTP_EXPIRED"
    OTP_WRONG_PURPOSE = "OTP_WRONG_PURPOSE"
    OTP_SEND_FAILED = "OTP_SEND_FAILED"

    # Profile update errors
    PROFILE_UPDATE_FAILED = "PROFILE_UPDATE_FAILED"
    EMAIL_UPDATE_REQUIRES_OTP = "EMAIL_UPDATE_REQUIRES_OTP"

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
    ErrorCodes.OTP_REQUIRED: "This action requires OTP verification. Please provide a valid OTP.",
    ErrorCodes.INVALID_OTP: "The OTP you entered is invalid or has already been used.",
    ErrorCodes.OTP_EXPIRED: "The OTP has expired. Please request a new one.",
    ErrorCodes.OTP_WRONG_PURPOSE: "The OTP is not valid for this type of operation.",
    ErrorCodes.OTP_SEND_FAILED: "Failed to send OTP. Please try again later.",
    ErrorCodes.PROFILE_UPDATE_FAILED: "Failed to update profile. Please check your data and try again.",
    ErrorCodes.EMAIL_UPDATE_REQUIRES_OTP: "Changing your email address requires OTP verification for security.",
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
    # New OTP-related error mappings
    elif "otp is not for profile update" in message_lower or "otp wrong purpose" in message_lower:
        return ErrorCodes.OTP_WRONG_PURPOSE
    elif "otp does not belong" in message_lower or "invalid otp" in message_lower:
        return ErrorCodes.INVALID_OTP
    elif "otp expired" in message_lower:
        return ErrorCodes.OTP_EXPIRED
    elif "failed to send otp" in message_lower:
        return ErrorCodes.OTP_SEND_FAILED
    elif "otp required" in message_lower or "provide otp" in message_lower:
        return ErrorCodes.OTP_REQUIRED
    # Profile update specific errors
    elif "profile update" in message_lower and "failed" in message_lower:
        return ErrorCodes.PROFILE_UPDATE_FAILED
    elif "email address requires otp" in message_lower:
        return ErrorCodes.EMAIL_UPDATE_REQUIRES_OTP
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


def get_frontend_friendly_message(original_data, fallback_message):
    """Extract the most user-friendly message for frontend display"""

    # If original_data is a dict with field errors, extract the most relevant message
    if isinstance(original_data, dict):
        # Priority 1: non_field_errors (general errors like login failures)
        if 'non_field_errors' in original_data and original_data['non_field_errors']:
            first_error = original_data['non_field_errors'][0]
            return str(first_error).replace('ErrorDetail(string=', '').replace("', code='invalid')", '').strip("'\"")

        # Priority 2: First field error (like password validation)
        for field_name, field_errors in original_data.items():
            if field_name != 'non_field_errors' and field_errors:
                first_error = field_errors[0]
                return str(first_error).replace('ErrorDetail(string=', '').replace("', code='invalid')", '').strip("'\"")

    # Priority 3: Check if original data is a list
    elif isinstance(original_data, list) and original_data:
        first_error = original_data[0]
        return str(first_error).replace('ErrorDetail(string=', '').replace("', code='invalid')", '').strip("'\"")

    # Fallback to the provided message
    return fallback_message


def custom_exception_handler(exc, context):
    """Custom exception handler that formats all errors consistently"""
    response = exception_handler(exc, context)

    if response is not None:
        error_code = get_error_code(exc)
        user_message = get_user_friendly_message(exc)
        field_errors = format_field_errors(response.data)

        # Get the most relevant user-friendly message
        frontend_message = get_frontend_friendly_message(response.data, user_message)

        custom_response_data = {
            'success': False,
            'message': frontend_message,  # Easy access for frontend
            'error': {
                'code': error_code,
                'message': user_message,
                'details': field_errors
            }
        }

        response.data = custom_response_data
        response.content_type = 'application/json'

    return response