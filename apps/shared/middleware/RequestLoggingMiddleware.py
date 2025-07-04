import json
from typing import Dict, Any

import structlog
from django.conf import settings
from django.http import HttpRequest
from django.utils.deprecation import MiddlewareMixin

# Configure structured logger
logger = structlog.get_logger(__name__)


class RequestLoggingMiddleware(MiddlewareMixin):
    """
    Comprehensive request logging middleware for audit and monitoring.

    This middleware logs detailed information about all requests for
    security auditing, debugging, and monitoring purposes.
    """

    def process_request(self, request: HttpRequest) -> None:
        """
        Log incoming request details.

        Args:
            request: Django HTTP request object
        """
        # Prepare request data for logging
        request_data = {
            'method': request.method,
            'path': request.path,
            'query_params': dict(request.GET),
            'content_type': request.content_type,
            'user_agent': request.META.get('HTTP_USER_AGENT', ''),
            'remote_addr': self._get_client_ip(request),
            'forwarded_for': request.META.get('HTTP_X_FORWARDED_FOR', ''),
            'referer': request.META.get('HTTP_REFERER', ''),
        }

        # Add user information if authenticated
        if hasattr(request, 'user') and request.user.is_authenticated:
            request_data['user_id'] = request.user.id
            request_data['username'] = request.user.username

        # Add service information if available
        if hasattr(request, 'service_context'):
            request_data['service_context'] = request.service_context

        # Log request body for POST/PUT/PATCH (excluding sensitive data)
        if request.method in ['POST', 'PUT', 'PATCH'] and request.content_type == 'application/json':
            try:
                body = json.loads(request.body.decode('utf-8'))
                # Remove sensitive fields
                cleaned_body = self._clean_sensitive_data(body)
                request_data['body'] = cleaned_body
            except (json.JSONDecodeError, UnicodeDecodeError):
                request_data['body'] = '<non-json-data>'

        logger.info(
            "request_details",
            correlation_id=getattr(request, 'correlation_id', ''),
            **request_data
        )

    def _get_client_ip(self, request: HttpRequest) -> str:
        """
        Extract client IP address from request.

        Args:
            request: Django HTTP request object

        Returns:
            Client IP address string
        """
        x_forwarded_for = request.META.get('HTTP_X_FORWARDED_FOR')
        if x_forwarded_for:
            ip = x_forwarded_for.split(',')[0]
        else:
            ip = request.META.get('REMOTE_ADDR')
        return ip or 'unknown'

    def _clean_sensitive_data(self, data: Dict[str, Any]) -> Dict[str, Any]:
        """
        Remove sensitive information from request data.

        Args:
            data: Request data dictionary

        Returns:
            Cleaned data dictionary
        """
        if not isinstance(data, dict):
            return data

        sensitive_fields = getattr(settings, 'SENSITIVE_FIELDS', [
            'password', 'token', 'secret', 'key', 'authorization',
            'credit_card', 'ssn', 'social_security'
        ])

        cleaned = {}
        for key, value in data.items():
            if any(sensitive in key.lower() for sensitive in sensitive_fields):
                cleaned[key] = '<redacted>'
            elif isinstance(value, dict):
                cleaned[key] = self._clean_sensitive_data(value)
            elif isinstance(value, list):
                cleaned[key] = [
                    self._clean_sensitive_data(item) if isinstance(item, dict) else item
                    for item in value
                ]
            else:
                cleaned[key] = value

        return cleaned
