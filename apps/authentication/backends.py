"""
Authentication backends for Core Platform Service.

This module provides authentication backends for the REST API,
including JWT authentication and service-to-service authentication.
"""

from typing import Optional, Tuple

import structlog
from django.contrib.auth import get_user_model
from django.contrib.auth.backends import BaseBackend
from django.contrib.auth.models import AnonymousUser
from rest_framework.authentication import BaseAuthentication
from rest_framework.exceptions import AuthenticationFailed
from rest_framework.request import Request

from apps.authentication.services import jwt_service, service_auth_service
from apps.users.models import ServiceAccount

# Configure structured logger
logger = structlog.get_logger(__name__)

User = get_user_model()


class JWTAuthentication(BaseAuthentication):
    """
    JWT-based authentication for the Core Platform API.

    Supports both user authentication and service-to-service authentication
    using JWT tokens.
    """

    def authenticate(self, request: Request) -> Optional[Tuple]:
        """
        Authenticate the request using JWT token.

        Args:
            request: The HTTP request object

        Returns:
            Tuple of (user, token) if authenticated, None otherwise
        """
        # Extract token from Authorization header
        auth_header = request.META.get('HTTP_AUTHORIZATION', '')

        if not auth_header:
            return None

        try:
            # Parse Authorization header
            auth_parts = auth_header.split()

            if len(auth_parts) != 2 or auth_parts[0].lower() != 'bearer':
                return None

            token = auth_parts[1]

            # Validate token
            validation_result = jwt_service.validate_token(token)

            if not validation_result['valid']:
                logger.warning(
                    "jwt_authentication_failed",
                    error=validation_result.get('error'),
                    error_code=validation_result.get('error_code'),
                    correlation_id=getattr(request, 'correlation_id', ''),
                    ip_address=self._get_client_ip(request)
                )
                raise AuthenticationFailed(validation_result.get('error', 'Invalid token'))

            token_type = validation_result['token_type']

            if token_type == 'access':
                return self._authenticate_user_token(request, validation_result)
            elif token_type == 'service':
                return self._authenticate_service_token(request, validation_result)
            else:
                raise AuthenticationFailed('Invalid token type')

        except AuthenticationFailed:
            raise
        except Exception as e:
            logger.error(
                "jwt_authentication_error",
                error=str(e),
                correlation_id=getattr(request, 'correlation_id', '')
            )
            raise AuthenticationFailed('Authentication failed')

    def authenticate_header(self, request: Request) -> str:
        """
        Return the authentication header for 401 responses.

        Args:
            request: The HTTP request object

        Returns:
            Authentication header string
        """
        return 'Bearer'

    def _authenticate_user_token(self, request: Request, validation_result: dict) -> Tuple:
        """
        Authenticate user token.

        Args:
            request: HTTP request
            validation_result: Token validation result

        Returns:
            Tuple of (user, token_data)
        """
        user = validation_result['user']

        # Record successful login
        ip_address = self._get_client_ip(request)
        user.record_successful_login(ip_address)

        # Add authentication metadata to request
        request.auth_type = 'jwt_user'
        request.token_data = validation_result

        logger.info(
            "user_authenticated_via_jwt",
            user_id=user.id,
            username=user.username,
            session_key=validation_result.get('session_key'),
            ip_address=ip_address,
            correlation_id=getattr(request, 'correlation_id', '')
        )

        return (user, validation_result)

    def _authenticate_service_token(self, request: Request, validation_result: dict) -> Tuple:
        """
        Authenticate service token.

        Args:
            request: HTTP request
            validation_result: Token validation result

        Returns:
            Tuple of (service_user, token_data)
        """
        service_account = validation_result['service_account']

        # Create a service user representation
        service_user = AnonymousUser()
        service_user.is_service = True
        service_user.service_account = service_account
        service_user.service_name = validation_result['service_name']
        service_user.scopes = validation_result['scopes']

        # Add authentication metadata to request
        request.auth_type = 'jwt_service'
        request.token_data = validation_result
        request.service_context = {
            'is_service_request': True,
            'service_account': service_account,
            'service_name': validation_result['service_name'],
            'scopes': validation_result['scopes']
        }

        logger.info(
            "service_authenticated_via_jwt",
            service_account=service_account.name,
            service_name=validation_result['service_name'],
            scopes=validation_result['scopes'],
            ip_address=self._get_client_ip(request),
            correlation_id=getattr(request, 'correlation_id', '')
        )

        return (service_user, validation_result)

    def _get_client_ip(self, request: Request) -> str:
        """
        Extract client IP address from request.

        Args:
            request: HTTP request object

        Returns:
            Client IP address string
        """
        x_forwarded_for = request.META.get('HTTP_X_FORWARDED_FOR')
        if x_forwarded_for:
            ip = x_forwarded_for.split(',')[0].strip()
        else:
            ip = request.META.get('REMOTE_ADDR', '0.0.0.0')
        return ip


class ServiceAuthentication(BaseAuthentication):
    """
    Service-to-service authentication for inter-microservice communication.

    Handles authentication using service tokens and API keys.
    """

    def authenticate(self, request: Request) -> Optional[Tuple]:
        """
        Authenticate service-to-service requests.

        Args:
            request: The HTTP request object

        Returns:
            Tuple of (user, token) if authenticated, None otherwise
        """
        # Check for service authentication headers
        service_token = request.META.get('HTTP_X_SERVICE_TOKEN')
        service_name = request.META.get('HTTP_X_SERVICE_NAME')
        api_key = request.META.get('HTTP_X_API_KEY')

        if service_token and service_name:
            return self._authenticate_with_token(request, service_token, service_name)
        elif api_key:
            return self._authenticate_with_api_key(request, api_key)

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

    def _authenticate_with_token(self, request: Request, token: str, service_name: str) -> Optional[Tuple]:
        """
        Authenticate using service token.

        Args:
            request: HTTP request
            token: Service token
            service_name: Service name

        Returns:
            Tuple of (service_user, token_data) or None
        """
        try:
            ip_address = self._get_client_ip(request)

            auth_result = service_auth_service.authenticate_service_request(
                token=token,
                ip_address=ip_address
            )

            if not auth_result['valid']:
                logger.warning(
                    "service_token_authentication_failed",
                    service_name=service_name,
                    error=auth_result.get('error'),
                    ip_address=ip_address,
                    correlation_id=getattr(request, 'correlation_id', '')
                )
                raise AuthenticationFailed(auth_result.get('error', 'Service authentication failed'))

            service_account = auth_result['service_account']

            # Create service user representation
            service_user = AnonymousUser()
            service_user.is_service = True
            service_user.service_account = service_account
            service_user.service_name = service_name
            service_user.scopes = auth_result['scopes']

            # Add service context to request
            request.service_context = {
                'is_service_request': True,
                'service_account': service_account,
                'service_name': service_name,
                'scopes': auth_result['scopes']
            }

            logger.info(
                "service_authenticated_with_token",
                service_account=service_account.name,
                service_name=service_name,
                ip_address=ip_address,
                correlation_id=getattr(request, 'correlation_id', '')
            )

            return (service_user, auth_result)

        except AuthenticationFailed:
            raise
        except Exception as e:
            logger.error(
                "service_token_authentication_error",
                service_name=service_name,
                error=str(e),
                correlation_id=getattr(request, 'correlation_id', '')
            )
            raise AuthenticationFailed('Service authentication failed')

    def _authenticate_with_api_key(self, request: Request, api_key: str) -> Optional[Tuple]:
        """
        Authenticate using API key.

        Args:
            request: HTTP request
            api_key: API key

        Returns:
            Tuple of (service_user, service_account) or None
        """
        try:
            service_account = ServiceAccount.objects.get(
                api_key=api_key,
                is_active=True
            )

            if service_account.is_expired:
                raise AuthenticationFailed('Service account has expired')

            ip_address = self._get_client_ip(request)

            # Check IP restrictions
            if not service_account.is_ip_allowed(ip_address):
                logger.warning(
                    "service_api_key_ip_denied",
                    service_account=service_account.name,
                    ip_address=ip_address,
                    correlation_id=getattr(request, 'correlation_id', '')
                )
                raise AuthenticationFailed('IP address not allowed')

            # Record usage
            service_account.record_usage(ip_address)

            # Create service user representation
            service_user = AnonymousUser()
            service_user.is_service = True
            service_user.service_account = service_account
            service_user.service_name = service_account.service_name
            service_user.scopes = service_account.scopes

            # Add service context to request
            request.service_context = {
                'is_service_request': True,
                'service_account': service_account,
                'service_name': service_account.service_name,
                'scopes': service_account.scopes
            }

            logger.info(
                "service_authenticated_with_api_key",
                service_account=service_account.name,
                service_name=service_account.service_name,
                ip_address=ip_address,
                correlation_id=getattr(request, 'correlation_id', '')
            )

            return (service_user, service_account)

        except ServiceAccount.DoesNotExist:
            logger.warning(
                "service_api_key_not_found",
                ip_address=self._get_client_ip(request),
                correlation_id=getattr(request, 'correlation_id', '')
            )
            raise AuthenticationFailed('Invalid API key')
        except AuthenticationFailed:
            raise
        except Exception as e:
            logger.error(
                "service_api_key_authentication_error",
                error=str(e),
                correlation_id=getattr(request, 'correlation_id', '')
            )
            raise AuthenticationFailed('Service authentication failed')

    def _get_client_ip(self, request: Request) -> str:
        """
        Extract client IP address from request.

        Args:
            request: HTTP request object

        Returns:
            Client IP address string
        """
        x_forwarded_for = request.META.get('HTTP_X_FORWARDED_FOR')
        if x_forwarded_for:
            ip = x_forwarded_for.split(',')[0].strip()
        else:
            ip = request.META.get('REMOTE_ADDR', '0.0.0.0')
        return ip


class CustomUserBackend(BaseBackend):
    """
    Custom authentication backend for Django admin and other non-API authentication.

    Provides enhanced user authentication with account locking and audit logging.
    """

    def authenticate(self, request, username=None, password=None, **kwargs):
        """
        Authenticate user with enhanced security features.

        Args:
            request: HTTP request
            username: Username
            password: Password
            **kwargs: Additional arguments

        Returns:
            User instance if authenticated, None otherwise
        """
        if username is None or password is None:
            return None

        try:
            # Get user by username or email
            try:
                user = User.objects.get(username=username)
            except User.DoesNotExist:
                try:
                    user = User.objects.get(email=username)
                except User.DoesNotExist:
                    logger.info(
                        "authentication_failed_user_not_found",
                        username=username,
                        ip_address=self._get_client_ip(request) if request else None
                    )
                    return None

            # Check if account is locked
            if user.is_account_locked:
                logger.warning(
                    "authentication_failed_account_locked",
                    user_id=user.id,
                    username=user.username,
                    ip_address=self._get_client_ip(request) if request else None
                )
                return None

            # Check password
            if user.check_password(password):
                # Successful authentication
                ip_address = self._get_client_ip(request) if request else None
                user.record_successful_login(ip_address)

                logger.info(
                    "user_authenticated_successfully",
                    user_id=user.id,
                    username=user.username,
                    ip_address=ip_address
                )

                return user
            else:
                # Failed authentication
                user.record_failed_login()

                logger.warning(
                    "authentication_failed_invalid_password",
                    user_id=user.id,
                    username=user.username,
                    failed_attempts=user.failed_login_attempts,
                    ip_address=self._get_client_ip(request) if request else None
                )

                return None

        except Exception as e:
            logger.error(
                "authentication_backend_error",
                username=username,
                error=str(e)
            )
            return None

    def get_user(self, user_id):
        """
        Get user by ID.

        Args:
            user_id: User ID

        Returns:
            User instance or None
        """
        try:
            return User.objects.get(pk=user_id, is_active=True)
        except User.DoesNotExist:
            return None

    def _get_client_ip(self, request) -> str:
        """
        Extract client IP address from request.

        Args:
            request: HTTP request object

        Returns:
            Client IP address string
        """
        if not request:
            return '0.0.0.0'

        x_forwarded_for = request.META.get('HTTP_X_FORWARDED_FOR')
        if x_forwarded_for:
            ip = x_forwarded_for.split(',')[0].strip()
        else:
            ip = request.META.get('REMOTE_ADDR', '0.0.0.0')
        return ip
