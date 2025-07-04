import logging
import time

import structlog
from django.conf import settings
from django.http import HttpRequest, HttpResponse
from django.utils.deprecation import MiddlewareMixin

# Configure structured logger
logger = structlog.get_logger(__name__)


class PerformanceLoggingMiddleware(MiddlewareMixin):
    """
    Middleware for performance monitoring and logging.

    This middleware:
    - Tracks request processing time
    - Monitors resource usage
    - Logs slow requests
    - Collects performance metrics
    """

    def process_request(self, request: HttpRequest) -> None:
        """
        Start performance tracking for the request.

        Args:
            request: Django HTTP request object
        """
        request.start_time = time.time()
        request.performance_metrics = {
            'db_queries': 0,
            'cache_hits': 0,
            'cache_misses': 0,
            'external_calls': 0
        }

    def process_response(self, request: HttpRequest, response: HttpResponse) -> HttpResponse:
        """
        Log performance metrics for the completed request.

        Args:
            request: Django HTTP request object
            response: Django HTTP response object

        Returns:
            Response with performance headers
        """
        if not hasattr(request, 'start_time'):
            return response

        # Calculate response time
        response_time = time.time() - request.start_time
        response_time_ms = round(response_time * 1000, 2)

        # Add performance header
        response['X-Response-Time'] = f"{response_time_ms}ms"

        # Collect performance metrics
        metrics = {
            'response_time_ms': response_time_ms,
            'status_code': response.status_code,
            'method': request.method,
            'path': request.path,
            'content_length': len(response.content) if hasattr(response, 'content') else 0,
            **getattr(request, 'performance_metrics', {})
        }

        # Log performance data
        log_level = self._get_log_level(response_time_ms, response.status_code)

        logger.log(
            log_level,
            "request_performance",
            correlation_id=getattr(request, 'correlation_id', ''),
            **metrics
        )

        # Alert on slow requests
        if response_time_ms > getattr(settings, 'SLOW_REQUEST_THRESHOLD_MS', 1000):
            logger.warning(
                "slow_request_detected",
                correlation_id=getattr(request, 'correlation_id', ''),
                **metrics
            )

        return response

    def _get_log_level(self, response_time_ms: float, status_code: int) -> int:
        """
        Determine appropriate log level based on performance and status.

        Args:
            response_time_ms: Response time in milliseconds
            status_code: HTTP status code

        Returns:
            Logging level constant
        """
        if status_code >= 500:
            return logging.ERROR
        elif status_code >= 400:
            return logging.WARNING
        elif response_time_ms > 1000:  # Slow requests
            return logging.WARNING
        else:
            return logging.INFO
