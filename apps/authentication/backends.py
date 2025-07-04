"""
Authentication backends for Core Platform Service.

This module provides authentication backends for the REST API.
This is a Phase 1 stub implementation that will be fully developed in Phase 2.
"""

from typing import Optional, Tuple
from django.contrib.auth.models import AnonymousUser
from rest_framework.authentication import BaseAuthentication
from rest_framework.request import Request
import structlog

# Configure structured logger
logger = structlog.get_logger(__name__)


class JWTAuthentication(BaseAuthentication):
    """
    JWT-based authentication for the Core Platform API.

    This is a Phase 1 stub implementation. Full JWT authentication
    will be implemented in Phase 2.
    """

    def authenticate(self, request: Request) -> Optional[Tuple]:
        """
        Authenticate the request using JWT token.

        This is a stub implementation for Phase 1 that allows all requests.
        In Phase 2, this will implement proper JWT validation.

        Args:
            request: The HTTP request object

        Returns:
            Tuple of (user, token) if authenticated, None otherwise
        """
        # Phase 1 stub - log the authentication attempt
        auth_header = request.META.get('HTTP_AUTHORIZATION', '')

        logger.debug(
            "jwt_authentication_attempt_stub",
            has_auth_header=bool(auth_header),
            correlation_id=getattr(request, 'correlation_id', '')
        )

        # In Phase 2, this will include:
        # - Extract JWT token from Authorization header
        # - Validate JWT token signature and expiry
        # - Get user from token payload
        # - Return (user, token) tuple

        # For Phase 1, return None to fall back to session authentication
        return None

    def authenticate_header(self, request: Request) -> str:
        """
        Return the authentication header for 401 responses.

        Args:
            request: The HTTP request object

        Returns:
            Authentication header string
        """
        return 'Bearer'


class ServiceAuthentication(BaseAuthentication):
    """
    Service-to-service authentication for inter-microservice communication.

    This is a Phase 1 stub implementation. Full service authentication
    will be implemented in Phase 2.
    """

    def authenticate(self, request: Request) -> Optional[Tuple]:
        """
        Authenticate service-to-service requests.

        This is a stub implementation for Phase 1.

        Args:
            request: The HTTP request object

        Returns:
            Tuple of (user, token) if authenticated, None otherwise
        """
        # Check for service authentication headers
        service_token = request.META.get('HTTP_X_SERVICE_TOKEN')
        service_name = request.META.get('HTTP_X_SERVICE_NAME')

        if service_token and service_name:
            logger.debug(
                "service_authentication_attempt_stub",
                service_name=service_name,
                correlation_id=getattr(request, 'correlation_id', '')
            )

            # Phase 1 stub - create a service user representation
            # In Phase 2, this will validate the service token properly
            service_user = AnonymousUser()
            service_user.is_service = True
            service_user.service_name = service_name

            return (service_user, service_token)

        return None

    def authenticate_header(self, request: Request) -> str:
        """
        Return the authentication header for 401 responses.

        Args:
            request: The HTTP request object

        Returns:
            Authentication header string
        """
        return 'Service'