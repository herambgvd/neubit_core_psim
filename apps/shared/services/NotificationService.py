from typing import Dict, List, Any, Optional, Union

import structlog
from django.conf import settings
from django.core.mail import send_mail
from django.template.loader import render_to_string
from django.utils import timezone

from apps.shared.services.HTTPClientService import HTTPClientService

# Configure structured logger
logger = structlog.get_logger(__name__)


class NotificationService:
    """
    Service for sending notifications through various channels.

    This service supports multiple notification channels including
    email, SMS, push notifications, and webhooks.
    """

    def __init__(self):
        """Initialize notification service."""
        self.http_client = HTTPClientService()

    def send_email(
            self,
            to_emails: Union[str, List[str]],
            subject: str,
            message: str,
            html_message: Optional[str] = None,
            from_email: Optional[str] = None,
            template_name: Optional[str] = None,
            template_context: Optional[Dict[str, Any]] = None
    ) -> bool:
        """
        Send email notification.

        Args:
            to_emails: Recipient email addresses
            subject: Email subject
            message: Plain text message
            html_message: HTML message
            from_email: Sender email address
            template_name: Email template name
            template_context: Template context variables

        Returns:
            True if email sent successfully
        """
        try:
            # Convert single email to list
            if isinstance(to_emails, str):
                to_emails = [to_emails]

            # Render template if provided
            if template_name and template_context:
                html_message = render_to_string(template_name, template_context)

            # Send email
            send_mail(
                subject=subject,
                message=message,
                from_email=from_email,
                recipient_list=to_emails,
                html_message=html_message,
                fail_silently=False
            )

            logger.info(
                "email_sent",
                recipients=to_emails,
                subject=subject,
                template=template_name
            )

            return True

        except Exception as e:
            logger.error(
                "email_send_failed",
                recipients=to_emails,
                subject=subject,
                error=str(e)
            )
            return False

    def send_error_notification(
            self,
            subject: str,
            message: str,
            error_details: Optional[Dict[str, Any]] = None
    ) -> bool:
        """
        Send error notification to administrators.

        Args:
            subject: Error subject
            message: Error message
            error_details: Additional error details

        Returns:
            True if notification sent successfully
        """
        try:
            # Get admin emails from settings
            admin_emails = [email for name, email in getattr(settings, 'ADMINS', [])]

            if not admin_emails:
                logger.warning("no_admin_emails_configured")
                return False

            # Prepare error context
            context = {
                'subject': subject,
                'message': message,
                'error_details': error_details or {},
                'timestamp': timezone.now(),
                'service': getattr(settings, 'SERVICE_DISCOVERY', {}).get('SERVICE_NAME', 'core')
            }

            return self.send_email(
                to_emails=admin_emails,
                subject=f'[PSIM Core] {subject}',
                message=message,
                template_name='notifications/error_notification.html',
                template_context=context
            )

        except Exception as e:
            logger.error("error_notification_failed", error=str(e))
            return False


notification_service = NotificationService()
