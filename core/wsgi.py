"""
WSGI configuration for Neubit PSIM Core Platform Service.

This module provides the WSGI application object that web servers
use to communicate with the Django application.

For production deployment, this WSGI application should be served
by a production WSGI server like Gunicorn or uWSGI.

Environment Variables:
    DJANGO_SETTINGS_MODULE: Django settings module to use
"""

import os
import sys
from pathlib import Path
from django.core.wsgi import get_wsgi_application

# Add the project directory to the Python path
project_dir = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(project_dir))

# Set default Django settings module
os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'core.settings.production')

# Create WSGI application
application = get_wsgi_application()

# For development with auto-reload
if os.environ.get('DJANGO_SETTINGS_MODULE', '').endswith('.development'):
    try:
        from django.core.management import execute_from_command_line
    except ImportError:
        # Django is not installed or not properly configured
        pass