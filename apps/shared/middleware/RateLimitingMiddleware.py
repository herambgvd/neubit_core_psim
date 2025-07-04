import time
from typing import Optional, Dict

import structlog
from django.conf import settings
from django.core.cache import cache
from django.http import HttpRequest, HttpResponse, JsonResponse
from django.utils.deprecation import MiddlewareMixin

# Configure structured logger
logger = structlog.get_logger(__name__)


class RateLimitingMiddleware(MiddlewareMixin):
    """
    Simple rate limiting middleware for API protection.

    This middleware provides basic rate limiting functionality to protect
    against abuse and ensure fair usage of the API.
    """

    def process_request(self, request: HttpRequest) -> Optional[HttpResponse]:
        """
        Check rate limits for the incoming request.

        Args:
            request: Django HTTP request object

        Returns:
            Rate limit error response if limit exceeded, None otherwise
        """
        # Skip rate limiting for certain paths
        if self._should_skip_rate_limit(request):
            return None

        # Get rate limit configuration
        rate_limit_config = self._get_rate_limit_config(request)
        if not rate_limit_config:
            return None

        # Check rate limit
        client_id = self._get_client_identifier(request)
        is_allowed, reset_time = self._check_rate_limit(
            client_id,
            rate_limit_config['requests'],
            rate_limit_config['window']
        )

        if not is_allowed:
            logger.warning(
                "rate_limit_exceeded",
                correlation_id=getattr(request, 'correlation_id', ''),
                client_id=client_id,
                path=request.path,
                method=request.method
            )

            response = JsonResponse(
                {
                    'error': 'Rate limit exceeded',
                    'code': 'RATE_LIMIT_EXCEEDED',
                    'reset_time': reset_time
                },
                status=429
            )
            response['Retry-After'] = str(int(reset_time - time.time()))
            return response

        return None

    def _should_skip_rate_limit(self, request: HttpRequest) -> bool:
        """
        Determine if rate limiting should be skipped.

        Args:
            request: Django HTTP request object

        Returns:
            True if rate limiting should be skipped
        """
        skip_paths = ['/health/', '/metrics/']
        return any(request.path.startswith(path) for path in skip_paths)

    def _get_rate_limit_config(self, request: HttpRequest) -> Optional[Dict[str, int]]:
        """
        Get rate limit configuration for the request.

        Args:
            request: Django HTTP request object

        Returns:
            Rate limit configuration dictionary
        """
        # Check if rate limiting is enabled
        if not getattr(settings, 'RATELIMIT_ENABLE', True):
            return None

        # Service requests have different limits
        if getattr(request, 'service_context', {}).get('is_service_request'):
            return {'requests': 1000, 'window': 60}  # 1000 requests per minute

        # Regular user requests
        if request.user.is_authenticated:
            return {'requests': 100, 'window': 60}  # 100 requests per minute

        # Anonymous requests
        return {'requests': 20, 'window': 60}  # 20 requests per minute

    def _get_client_identifier(self, request: HttpRequest) -> str:
        """
        Get unique identifier for the client.

        Args:
            request: Django HTTP request object

        Returns:
            Client identifier string
        """
        # Use service name for service requests
        service_context = getattr(request, 'service_context', {})
        if service_context.get('is_service_request'):
            return f"service:{service_context.get('service_name', 'unknown')}"

        # Use user ID for authenticated requests
        if request.user.is_authenticated:
            return f"user:{request.user.id}"

        # Use IP address for anonymous requests
        return f"ip:{self._get_client_ip(request)}"

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

    def _check_rate_limit(self, client_id: str, max_requests: int, window_seconds: int) -> tuple[bool, float]:
        """
        Check if client has exceeded rate limit.

        Args:
            client_id: Unique client identifier
            max_requests: Maximum requests allowed
            window_seconds: Time window in seconds

        Returns:
            Tuple of (is_allowed, reset_time)
        """
        current_time = time.time()
        window_start = current_time - window_seconds
        cache_key = f"rate_limit:{client_id}"

        # Get current request timestamps
        request_times = cache.get(cache_key, [])

        # Remove old requests outside the window
        request_times = [t for t in request_times if t > window_start]

        # Check if limit exceeded
        if len(request_times) >= max_requests:
            reset_time = request_times[0] + window_seconds
            return False, reset_time

        # Add current request
        request_times.append(current_time)

        # Update cache
        cache.set(cache_key, request_times, timeout=window_seconds + 60)

        return True, current_time + window_seconds
