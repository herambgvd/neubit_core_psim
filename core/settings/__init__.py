"""
Settings package initialization for Neubit PSIM Core Platform Service.

This module automatically loads the appropriate settings based on the
DJANGO_SETTINGS_MODULE environment variable or defaults to development.
"""

import os

# Determine which settings module to load
settings_module = os.environ.get('DJANGO_SETTINGS_MODULE', 'core.settings.development')

# Extract the settings type from the module name
settings_type = settings_module.split('.')[-1] if '.' in settings_module else 'development'

# Import the appropriate settings
if settings_type == 'production':
    from .production import *
elif settings_type == 'testing':
    from .testing import *
else:
    from .development import *

# Make the settings type available
SETTINGS_TYPE = settings_type
