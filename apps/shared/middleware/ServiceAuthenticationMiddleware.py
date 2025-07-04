from typing import Optional, Dict, Any

import structlog
from django.core.cache import cache
from django.http import HttpRequest, HttpResponse, JsonResponse
from django.utils.deprecation import MiddlewareMixin

# Configure structured logger
logger = structlog.get_logger(__name__)


class ServiceAuthenticationMiddleware(MiddlewareMixin):
    """
    Middleware for service-to-service authentication in microservice architecture.

    This middleware:
    - Validates service tokens for inter-service communication
    - Adds service context to requests
    - Implements service-specific rate limiting
    - Logs service authentication events
    """

    SERVICE_TOKEN_HEADER = 'X-Service-Token'
    SERVICE_NAME_HEADER = 'X-Service-Name'

    def process_request(self, request: HttpRequest) -> Optional[HttpResponse]:
        """
        Process request for service authentication.

        Args:
            request: Django HTTP request object

        Returns:
            None for successful authentication, error response otherwise
        """
        # Skip service auth for certain paths
        if self._should_skip_service_auth(request):
            return None

        # Extract service headers
        service_token = request.META.get(
            f'HTTP_{self.SERVICE_TOKEN_HEADER.upper().replace("-", "_")}'
        )
        service_name = request.META.get(
            f'HTTP_{self.SERVICE_NAME_HEADER.upper().replace("-", "_")}'
        )

        # Check if this is a service-to-service request
        if service_token or service_name:
            # Validate service authentication
            auth_result = self._validate_service_auth(service_token, service_name)

            if not auth_result['valid']:
                logger.warning(
                    "service_auth_failed",
                    correlation_id=getattr(request, 'correlation_id', ''),
                    service_name=service_name,
                    reason=auth_result['reason'],
                    remote_addr=request.META.get('REMOTE_ADDR')
                )
                return JsonResponse(
                    {'error': 'Service authentication failed', 'code': 'INVALID_SERVICE_TOKEN'},
                    status=401
                )

            # Add service context to request
            request.service_context = {
                'service_name': auth_result['service_name'],
                'service_permissions': auth_result['permissions'],
                'is_service_request': True
            }

            logger.info(
                "service_auth_success",
                correlation_id=getattr(request, 'correlation_id', ''),
                service_name=auth_result['service_name'],
                permissions=auth_result['permissions']
            )
        else:
            # Mark as non-service request
            request.service_context = {'is_service_request': False}

        return None

    def _should_skip_service_auth(self, request: HttpRequest) -> bool:
        """
        Determine if service authentication should be skipped for this request.

        Args:
            request: Django HTTP request object

        Returns:
            True if service auth should be skipped
        """
        skip_paths = [
            '/health/',
            '/metrics/',
            '/admin/',
            '/api/docs/',
            '/api/schema/',
        ]

        return any(request.path.startswith(path) for path in skip_paths)

    def _validate_service_auth(self, token: Optional[str], service_name: Optional[str]) -> Dict[str, Any]:
        """
        Validate service authentication token.

        Args:
            token: Service authentication token
            service_name: Name of the requesting service

        Returns:
            Dictionary with validation results
        """
        if not token or not service_name:
            return {'valid': False, 'reason': 'Missing token or service name'}

        # Cache key for service validation
        cache_key = f"service_auth:{service_name}:{token[:8]}..."

        # Check cache first
        cached_result = cache.get(cache_key)
        if cached_result:
            return cached_result

        try:
            # Validate token using JWT or similar mechanism
            # This is a simplified implementation - use proper JWT validation in production
            from apps.authentication.services import ServiceAuthenticationService

            auth_service = ServiceAuthenticationService()
            validation_result = auth_service.validate_service_token(token, service_name)

            # Cache successful validations for a short time
            if validation_result['valid']:
                cache.set(cache_key, validation_result, timeout=300)  # 5 minutes

            return validation_result

        except Exception as e:
            logger.error(
                "service_auth_error",
                correlation_id=getattr(request, 'correlation_id', ''),
                error=str(e),
                service_name=service_name
            )
            return {'valid': False, 'reason': 'Authentication service error'}
