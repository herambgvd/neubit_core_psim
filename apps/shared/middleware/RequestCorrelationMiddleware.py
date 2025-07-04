import uuid

import structlog
from django.http import HttpRequest, HttpResponse
from django.utils.deprecation import MiddlewareMixin

# Configure structured logger
logger = structlog.get_logger(__name__)


class RequestCorrelationMiddleware(MiddlewareMixin):
    """
    Middleware to add correlation IDs to requests for distributed tracing.

    This middleware:
    - Generates or extracts correlation IDs from request headers
    - Adds correlation ID to response headers
    - Logs correlation information for request tracking
    - Supports distributed tracing across microservices
    """

    CORRELATION_ID_HEADER = 'X-Correlation-ID'
    REQUEST_ID_HEADER = 'X-Request-ID'

    def process_request(self, request: HttpRequest) -> None:
        """
        Process incoming request to add correlation tracking.

        Args:
            request: Django HTTP request object
        """
        # Extract or generate correlation ID
        correlation_id = (
                request.META.get(f'HTTP_{self.CORRELATION_ID_HEADER.upper().replace("-", "_")}') or
                str(uuid.uuid4())
        )

        # Extract or generate request ID
        request_id = (
                request.META.get(f'HTTP_{self.REQUEST_ID_HEADER.upper().replace("-", "_")}') or
                str(uuid.uuid4())
        )

        # Store IDs in request for access throughout the request lifecycle
        request.correlation_id = correlation_id
        request.request_id = request_id

        # Add to request META for easy access
        request.META['CORRELATION_ID'] = correlation_id
        request.META['REQUEST_ID'] = request_id

        # Log request start with correlation information
        logger.info(
            "request_started",
            correlation_id=correlation_id,
            request_id=request_id,
            method=request.method,
            path=request.path,
            user_agent=request.META.get('HTTP_USER_AGENT', ''),
            remote_addr=self._get_client_ip(request)
        )

    def process_response(self, request: HttpRequest, response: HttpResponse) -> HttpResponse:
        """
        Process response to add correlation headers.

        Args:
            request: Django HTTP request object
            response: Django HTTP response object

        Returns:
            Modified response with correlation headers
        """
        # Add correlation headers to response
        if hasattr(request, 'correlation_id'):
            response[self.CORRELATION_ID_HEADER] = request.correlation_id

        if hasattr(request, 'request_id'):
            response[self.REQUEST_ID_HEADER] = request.request_id

        # Log response completion
        if hasattr(request, 'correlation_id'):
            logger.info(
                "request_completed",
                correlation_id=request.correlation_id,
                request_id=getattr(request, 'request_id', ''),
                status_code=response.status_code,
                content_length=len(response.content) if hasattr(response, 'content') else 0
            )

        return response

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
