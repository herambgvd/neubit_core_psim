"""
Custom exception handlers for Core Platform Service.

This module provides custom exception handling for the REST API,
ensuring consistent error responses and proper logging of exceptions.
"""

from typing import Dict, Any, Optional

import structlog
from django.core.exceptions import PermissionDenied, ValidationError
from django.http import Http404
from rest_framework.views import exception_handler

# Configure structured logger
logger = structlog.get_logger(__name__)


def custom_exception_handler(exc, context):
    """
    Custom exception handler for DRF that provides consistent error responses.

    Args:
        exc: The exception instance
        context: Context information about the request

    Returns:
        Response object with standardized error format
    """
    # Get the standard error response
    response = exception_handler(exc, context)

    # Get request information for logging
    request = context.get('request')
    correlation_id = getattr(request, 'correlation_id', '') if request else ''

    # Log the exception
    logger.error(
        "api_exception_occurred",
        correlation_id=correlation_id,
        exception_type=type(exc).__name__,
        exception_message=str(exc),
        path=request.path if request else '',
        method=request.method if request else '',
        user_id=request.user.id if request and hasattr(request, 'user') and request.user.is_authenticated else None
    )

    if response is not None:
        # Customize the error response format
        custom_response_data = {
            'error': {
                'code': _get_error_code(exc),
                'message': _get_error_message(exc, response.data),
                'details': _get_error_details(exc, response.data),
                'correlation_id': correlation_id,
            },
            'success': False,
            'data': None
        }

        response.data = custom_response_data

    return response


def _get_error_code(exc) -> str:
    """
    Get standardized error code based on exception type.

    Args:
        exc: The exception instance

    Returns:
        Error code string
    """
    error_codes = {
        ValidationError: 'VALIDATION_ERROR',
        PermissionDenied: 'PERMISSION_DENIED',
        Http404: 'NOT_FOUND',
        'AuthenticationFailed': 'AUTHENTICATION_FAILED',
        'NotAuthenticated': 'NOT_AUTHENTICATED',
        'PermissionDenied': 'PERMISSION_DENIED',
        'NotFound': 'NOT_FOUND',
        'MethodNotAllowed': 'METHOD_NOT_ALLOWED',
        'NotAcceptable': 'NOT_ACCEPTABLE',
        'UnsupportedMediaType': 'UNSUPPORTED_MEDIA_TYPE',
        'Throttled': 'RATE_LIMITED',
        'ValidationError': 'VALIDATION_ERROR',
        'ParseError': 'PARSE_ERROR',
    }

    exc_class_name = type(exc).__name__

    # Check for DRF exception types
    if hasattr(exc, 'default_code'):
        return exc.default_code.upper()

    return error_codes.get(exc_class_name, 'INTERNAL_SERVER_ERROR')


def _get_error_message(exc, response_data) -> str:
    """
    Get user-friendly error message.

    Args:
        exc: The exception instance
        response_data: Original response data from DRF

    Returns:
        Error message string
    """
    # If it's a DRF exception with detail
    if hasattr(exc, 'detail'):
        if isinstance(exc.detail, str):
            return exc.detail
        elif isinstance(exc.detail, dict):
            # Get the first error message from field errors
            for field, errors in exc.detail.items():
                if isinstance(errors, list) and errors:
                    return f"{field}: {errors[0]}"
                elif isinstance(errors, str):
                    return f"{field}: {errors}"
        elif isinstance(exc.detail, list) and exc.detail:
            return str(exc.detail[0])

    # Fallback to original response data
    if isinstance(response_data, dict):
        if 'detail' in response_data:
            return response_data['detail']
        elif 'message' in response_data:
            return response_data['message']

    # Default messages for common exceptions
    default_messages = {
        'ValidationError': 'The provided data is invalid.',
        'PermissionDenied': 'You do not have permission to perform this action.',
        'Http404': 'The requested resource was not found.',
        'AuthenticationFailed': 'Authentication credentials were invalid.',
        'NotAuthenticated': 'Authentication credentials were not provided.',
        'MethodNotAllowed': 'This HTTP method is not allowed for this endpoint.',
        'Throttled': 'Rate limit exceeded. Please try again later.',
    }

    return default_messages.get(type(exc).__name__, 'An error occurred while processing your request.')


def _get_error_details(exc, response_data) -> Optional[Dict[str, Any]]:
    """
    Get detailed error information for debugging.

    Args:
        exc: The exception instance
        response_data: Original response data from DRF

    Returns:
        Dictionary with error details or None
    """
    details = {}

    # Add field-specific errors for validation errors
    if hasattr(exc, 'detail') and isinstance(exc.detail, dict):
        details['field_errors'] = exc.detail

    # Add status code
    if hasattr(exc, 'status_code'):
        details['status_code'] = exc.status_code

    # Add any additional context from original response
    if isinstance(response_data, dict):
        for key, value in response_data.items():
            if key not in ['detail', 'message'] and not key.startswith('_'):
                details[key] = value

    return details if details else None


class BusinessLogicError(Exception):
    """
    Custom exception for business logic errors.

    This exception should be raised when business rules are violated
    or when domain-specific errors occur.
    """

    def __init__(self, message: str, code: str = 'BUSINESS_LOGIC_ERROR', details: Optional[Dict] = None):
        """
        Initialize business logic error.

        Args:
            message: Human-readable error message
            code: Error code for programmatic handling
            details: Additional error details
        """
        self.message = message
        self.code = code
        self.details = details or {}
        super().__init__(message)


class ServiceUnavailableError(Exception):
    """
    Custom exception for service unavailability.

    This exception should be raised when external services are unavailable
    or when the system is temporarily unable to process requests.
    """

    def __init__(self, message: str = 'Service temporarily unavailable', service_name: Optional[str] = None):
        """
        Initialize service unavailable error.

        Args:
            message: Human-readable error message
            service_name: Name of the unavailable service
        """
        self.message = message
        self.service_name = service_name
        super().__init__(message)


class RateLimitExceededError(Exception):
    """
    Custom exception for rate limiting.

    This exception should be raised when rate limits are exceeded.
    """

    def __init__(self, message: str = 'Rate limit exceeded', retry_after: Optional[int] = None):
        """
        Initialize rate limit error.

        Args:
            message: Human-readable error message
            retry_after: Seconds to wait before retrying
        """
        self.message = message
        self.retry_after = retry_after
        super().__init__(message)
