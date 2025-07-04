import json
import time
import uuid
import logging
from typing import Callable, Optional, Dict, Any
from django.http import HttpRequest, HttpResponse, JsonResponse
from django.utils.deprecation import MiddlewareMixin
from django.conf import settings
from django.core.cache import cache
from django.contrib.auth.models import AnonymousUser
from rest_framework.authtoken.models import Token
import structlog

# Configure structured logger
logger = structlog.get_logger(__name__)

class APIVersioningMiddleware(MiddlewareMixin):
    """
    Middleware for API versioning support.

    This middleware handles API versioning through headers and URL paths,
    ensuring backward compatibility and proper version routing.
    """

    VERSION_HEADER = 'X-API-Version'
    DEFAULT_VERSION = 'v1'
    SUPPORTED_VERSIONS = ['v1']

    def process_request(self, request: HttpRequest) -> Optional[HttpResponse]:
        """
        Process API version from request.

        Args:
            request: Django HTTP request object

        Returns:
            Version error response if unsupported version, None otherwise
        """
        # Skip versioning for non-API paths
        if not request.path.startswith('/api/'):
            return None

        # Extract version from URL path or header
        version = self._extract_version(request)

        # Validate version
        if version not in self.SUPPORTED_VERSIONS:
            logger.warning(
                "unsupported_api_version",
                correlation_id=getattr(request, 'correlation_id', ''),
                requested_version=version,
                supported_versions=self.SUPPORTED_VERSIONS
            )

            return JsonResponse(
                {
                    'error': f'Unsupported API version: {version}',
                    'code': 'UNSUPPORTED_VERSION',
                    'supported_versions': self.SUPPORTED_VERSIONS
                },
                status=400
            )

        # Add version to request
        request.api_version = version

        return None

    def process_response(self, request: HttpRequest, response: HttpResponse) -> HttpResponse:
        """
        Add version information to response.

        Args:
            request: Django HTTP request object
            response: Django HTTP response object

        Returns:
            Response with version headers
        """
        if hasattr(request, 'api_version'):
            response[self.VERSION_HEADER] = request.api_version

        return response

    def _extract_version(self, request: HttpRequest) -> str:
        """
        Extract API version from request.

        Args:
            request: Django HTTP request object

        Returns:
            API version string
        """
        # Check URL path first (e.g., /api/v1/users/)
        path_parts = request.path.strip('/').split('/')
        if len(path_parts) >= 2 and path_parts[0] == 'api' and path_parts[1].startswith('v'):
            return path_parts[1]

        # Check header
        version = request.META.get(f'HTTP_{self.VERSION_HEADER.upper().replace("-", "_")}')
        if version:
            return version

        # Return default version
        return self.DEFAULT_VERSION