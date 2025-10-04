"""
Custom validators for Django REST Framework.
Centralized validation logic to maintain DRY principle.
"""
import re


def validate_password_strength(password):
    """
    Validate password meets security requirements.

    Requirements:
    - At least 8 characters long
    - At least one uppercase letter
    - At least one lowercase letter
    - At least one number
    - At least one special character

    Args:
        password (str): The password to validate

    Returns:
        list: List of error messages. Empty list if password is valid.

    Example:
        >>> errors = validate_password_strength("weak")
        >>> if errors:
        ...     raise ValidationError(errors)
    """
    errors = []

    # Length check
    if len(password) < 8:
        errors.append("Password must be at least 8 characters long")

    # Character requirements
    if not re.search(r'[A-Z]', password):
        errors.append("Password must contain at least one uppercase letter")

    if not re.search(r'[a-z]', password):
        errors.append("Password must contain at least one lowercase letter")

    if not re.search(r'\d', password):
        errors.append("Password must contain at least one number")

    if not re.search(r'[!@#$%^&*(),.?":{}|<>]', password):
        errors.append("Password must contain at least one special character")

    return errors
