"""
Shared application configuration.
"""

from django.apps import AppConfig


class SharedConfig(AppConfig):
    """Configuration for the shared application."""

    default_auto_field = 'django.db.models.BigAutoField'
    name = 'apps.shared'
    verbose_name = 'Shared Components'

    def ready(self):
        """Perform initialization when Django starts."""
        # Import any signals or other initialization code here
        pass