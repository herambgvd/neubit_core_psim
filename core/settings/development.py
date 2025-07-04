
"""
Development settings for Neubit PSIM Core Platform Service.

This module contains settings specific to the development environment.
It inherits from base settings and overrides necessary configurations
for local development and debugging.

Key Features:
- Debug mode enabled
- Relaxed security settings for development
- Local database and cache configuration
- Development-specific middleware
- Enhanced logging for debugging
"""

from .base import *

# Development mode
DEBUG = True

# Allowed hosts for development
ALLOWED_HOSTS = [
    'localhost',
    '127.0.0.1',
    '0.0.0.0',
    'core-platform-dev',  # Docker container name
]

# Database configuration for development
DATABASES = {
    'default': {
        'ENGINE': 'django.db.backends.postgresql',
        'NAME': env('DB_NAME', default='neubit_psim_core_dev'),
        'USER': env('DB_USER', default='postgres'),
        'PASSWORD': env('DB_PASSWORD', default='postgres'),
        'HOST': env('DB_HOST', default='localhost'),
        'PORT': env('DB_PORT', default='5432'),
        'OPTIONS': {
            'sslmode': 'prefer',
        },
        'TEST': {
            'NAME': 'test_neubit_psim_core_dev',
        }
    }
}

# Cache configuration for development
CACHES = {
    'default': {
        'BACKEND': 'django_redis.cache.RedisCache',
        'LOCATION': env('REDIS_URL', default='redis://localhost:6379/1'),
        'OPTIONS': {
            'CLIENT_CLASS': 'django_redis.client.DefaultClient',
            'PARSER_CLASS': 'redis.connection.HiredisParser',
        },
        'KEY_PREFIX': 'neubit_core_dev',
        'TIMEOUT': 300,
        'VERSION': 1,
    }
}

# Development-specific installed apps
INSTALLED_APPS += [
    'debug_toolbar',
]

# Development middleware
MIDDLEWARE = [
                 'debug_toolbar.middleware.DebugToolbarMiddleware',
             ] + MIDDLEWARE

# Debug toolbar configuration
INTERNAL_IPS = [
    '127.0.0.1',
    'localhost',
]

DEBUG_TOOLBAR_CONFIG = {
    'DISABLE_PANELS': [
        'debug_toolbar.panels.redirects.RedirectsPanel',
    ],
    'SHOW_TEMPLATE_CONTEXT': True,
}

# Email backend for development (console backend)
EMAIL_BACKEND = 'django.core.mail.backends.console.EmailBackend'

# Celery configuration for development
CELERY_TASK_ALWAYS_EAGER = env('CELERY_ALWAYS_EAGER', default=False, cast=bool)
CELERY_TASK_EAGER_PROPAGATES = True

# CORS settings for development
CORS_ALLOW_ALL_ORIGINS = True
CORS_ALLOW_CREDENTIALS = True

# JWT settings for development (shorter expiry for testing)
JWT_SETTINGS.update({
    'ACCESS_TOKEN_LIFETIME': 60 * 60,  # 1 hour for development
    'REFRESH_TOKEN_LIFETIME': 24 * 60 * 60,  # 24 hours for development
})

# Disable security features for development
SECURE_SSL_REDIRECT = False
SESSION_COOKIE_SECURE = False
CSRF_COOKIE_SECURE = False
SECURE_HSTS_SECONDS = 0

# Service discovery for development
SERVICE_DISCOVERY.update({
    'KONG_ADMIN_URL': env('KONG_ADMIN_URL', default='http://kong:8001'),
    'SERVICE_URL': env('SERVICE_URL', default='http://core-platform:8000'),
})

# Development logging configuration
LOGGING['loggers']['django.db.backends'] = {
    'handlers': ['console'],
    'level': 'DEBUG',
    'propagate': False,
}

# Performance logging for development
LOGGING['loggers']['apps.shared.performance'] = {
    'handlers': ['console'],
    'level': 'DEBUG',
    'propagate': False,
}

# File storage for development (local filesystem)
DEFAULT_FILE_STORAGE = 'django.core.files.storage.FileSystemStorage'

# Static files serving for development
STATICFILES_STORAGE = 'django.contrib.staticfiles.storage.StaticFilesStorage'

# Development-specific rate limiting (more permissive)
RATELIMIT_ENABLE = False

# Test settings override
if 'test' in sys.argv:
    # Use in-memory SQLite for faster tests
    DATABASES = {
        'default': {
            'ENGINE': 'django.db.backends.sqlite3',
            'NAME': ':memory:',
        }
    }

    # Use dummy cache for tests
    CACHES = {
        'default': {
            'BACKEND': 'django.core.cache.backends.dummy.DummyCache',
        }
    }


    # Disable migrations for faster tests
    class DisableMigrations:
        def __contains__(self, item):
            return True

        def __getitem__(self, item):
            return None


    MIGRATION_MODULES = DisableMigrations()

    # Use console email backend for tests
    EMAIL_BACKEND = 'django.core.mail.backends.locmem.EmailBackend'

    # Disable Celery for tests
    CELERY_TASK_ALWAYS_EAGER = True
    CELERY_TASK_EAGER_PROPAGATES = True

# Development-specific security (relaxed)
SECRET_KEY = env('SECRET_KEY', default='dev-secret-key-change-in-production')

# Additional development tools
SHELL_PLUS_PRINT_SQL = True
SHELL_PLUS_PRINT_SQL_TRUNCATE = 1000

# Development API documentation settings
SPECTACULAR_SETTINGS.update({
    'SERVE_INCLUDE_SCHEMA': True,
    'SERVE_PERMISSIONS': ['rest_framework.permissions.AllowAny'],
})

# Development-specific health check settings
HEALTH_CHECK.update({
    'DISK_USAGE_MAX': 95,  # More permissive for development
    'MEMORY_MIN': 50,  # Lower requirement for development
})

print("Development settings loaded")  # Confirmation for development environment