import structlog
from django.http import HttpRequest, HttpResponse
from django.utils.deprecation import MiddlewareMixin

# Configure structured logger
logger = structlog.get_logger(__name__)


class SecurityHeadersMiddleware(MiddlewareMixin):
    """
    Middleware to add security headers to all responses.

    This middleware adds essential security headers to protect against
    common web vulnerabilities and attacks.
    """

    def process_response(self, request: HttpRequest, response: HttpResponse) -> HttpResponse:
        """
        Add security headers to the response.

        Args:
            request: Django HTTP request object
            response: Django HTTP response object

        Returns:
            Response with security headers added
        """
        # Content Security Policy
        if not response.get('Content-Security-Policy'):
            response['Content-Security-Policy'] = (
                "default-src 'self'; "
                "script-src 'self' 'unsafe-inline' 'unsafe-eval'; "
                "style-src 'self' 'unsafe-inline'; "
                "img-src 'self' data: https:; "
                "font-src 'self' https:; "
                "connect-src 'self' https: wss:; "
                "frame-ancestors 'none';"
            )

        # Prevent MIME type sniffing
        if not response.get('X-Content-Type-Options'):
            response['X-Content-Type-Options'] = 'nosniff'

        # XSS Protection
        if not response.get('X-XSS-Protection'):
            response['X-XSS-Protection'] = '1; mode=block'

        # Referrer Policy
        if not response.get('Referrer-Policy'):
            response['Referrer-Policy'] = 'strict-origin-when-cross-origin'

        # Permissions Policy
        if not response.get('Permissions-Policy'):
            response['Permissions-Policy'] = (
                "camera=(), microphone=(), geolocation=(), "
                "payment=(), usb=(), magnetometer=(), gyroscope=()"
            )

        # Server information hiding
        response['Server'] = 'Neubit-PSIM'

        return response
