"""
Testing settings for Neubit PSIM Core Platform Service.

This module contains settings specific to the testing environment.
It inherits from base settings and overrides configurations for
fast and isolated testing.

Key Features:
- In-memory database for speed
- Disabled external services
- Simplified logging
- Fast password hashing
- Isolated test environment
"""

from .base import *

# Testing mode
DEBUG = False
TESTING = True

# Test database - use SQLite in memory for speed
DATABASES = {
    'default': {
        'ENGINE': 'django.db.backends.sqlite3',
        'NAME': ':memory:',
        'OPTIONS': {
            'timeout': 20,
        }
    }
}

# Test cache - use dummy cache
CACHES = {
    'default': {
        'BACKEND': 'django.core.cache.backends.dummy.DummyCache',
    }
}


# Disable migrations for faster tests
class DisableMigrations:
    """Disable migrations during testing for speed."""

    def __contains__(self, item):
        return True

    def __getitem__(self, item):
        return None


MIGRATION_MODULES = DisableMigrations()

# Fast password hashing for tests
PASSWORD_HASHERS = [
    'django.contrib.auth.hashers.MD5PasswordHasher',  # Fast but insecure - only for tests
]

# Email backend for testing
EMAIL_BACKEND = 'django.core.mail.backends.locmem.EmailBackend'

# Celery - run tasks synchronously during tests
CELERY_TASK_ALWAYS_EAGER = True
CELERY_TASK_EAGER_PROPAGATES = True
CELERY_BROKER_URL = 'memory://'
CELERY_RESULT_BACKEND = 'cache+memory://'

# Disable external services during testing
RATELIMIT_ENABLE = False

# Security settings for testing
SECRET_KEY = 'test-secret-key-not-for-production'
ALLOWED_HOSTS = ['testserver', 'localhost', '127.0.0.1']

# CORS settings for testing
CORS_ALLOW_ALL_ORIGINS = True
CORS_ALLOW_CREDENTIALS = True

# Static files for testing
STATICFILES_STORAGE = 'django.contrib.staticfiles.storage.StaticFilesStorage'
STATIC_ROOT = BASE_DIR / 'test_staticfiles'

# Media files for testing
MEDIA_ROOT = BASE_DIR / 'test_media'
DEFAULT_FILE_STORAGE = 'django.core.files.storage.FileSystemStorage'

# Logging configuration for testing
LOGGING = {
    'version': 1,
    'disable_existing_loggers': False,
    'handlers': {
        'console': {
            'class': 'logging.StreamHandler',
            'level': 'WARNING',  # Only show warnings and errors during tests
        },
    },
    'root': {
        'handlers': ['console'],
        'level': 'WARNING',
    },
    'loggers': {
        'django': {
            'handlers': ['console'],
            'level': 'WARNING',
            'propagate': False,
        },
        'core': {
            'handlers': ['console'],
            'level': 'WARNING',
            'propagate': False,
        },
        'apps': {
            'handlers': ['console'],
            'level': 'WARNING',
            'propagate': False,
        },
    },
}

# Service discovery for testing
SERVICE_DISCOVERY.update({
    'KONG_ADMIN_URL': 'http://test-kong:8001',
    'SERVICE_URL': 'http://test-core-platform:8000',
    'ENVIRONMENT': 'testing',
})

# JWT settings for testing
JWT_SETTINGS.update({
    'ACCESS_TOKEN_LIFETIME': 3600,  # 1 hour for testing
    'REFRESH_TOKEN_LIFETIME': 86400,  # 24 hours for testing
    'ALGORITHM': 'HS256',  # Simple algorithm for testing
})

# Health check settings for testing
HEALTH_CHECK.update({
    'DISK_USAGE_MAX': 99,  # Very permissive for testing
    'MEMORY_MIN': 10,  # Low requirement for testing
})

# File upload settings for testing
FILE_UPLOAD_MAX_MEMORY_SIZE = 1024 * 1024  # 1MB for testing
DATA_UPLOAD_MAX_MEMORY_SIZE = 1024 * 1024  # 1MB for testing

# Disable cache framework for testing
CACHES['default']['TIMEOUT'] = 1  # Very short timeout

# Testing-specific middleware (remove some middleware for speed)
MIDDLEWARE = [
    'corsheaders.middleware.CorsMiddleware',
    'django.middleware.security.SecurityMiddleware',
    'django.contrib.sessions.middleware.SessionMiddleware',
    'django.middleware.common.CommonMiddleware',
    'django.middleware.csrf.CsrfViewMiddleware',
    'django.contrib.auth.middleware.AuthenticationMiddleware',
    'django.contrib.messages.middleware.MessageMiddleware',
    'apps.shared.middleware.RequestCorrelationMiddleware',
    # Remove performance and security middleware for testing speed
]

# Test-specific settings
TEST_RUNNER = 'django.test.runner.DiscoverRunner'

# Disable certain security features for testing
SECURE_SSL_REDIRECT = False
SESSION_COOKIE_SECURE = False
CSRF_COOKIE_SECURE = False
SECURE_HSTS_SECONDS = 0

# REST Framework settings for testing
REST_FRAMEWORK_TEST = REST_FRAMEWORK.copy()
REST_FRAMEWORK_TEST.update({
    'DEFAULT_AUTHENTICATION_CLASSES': [
        'rest_framework.authentication.SessionAuthentication',
    ],
    'DEFAULT_PERMISSION_CLASSES': [
        'rest_framework.permissions.AllowAny',  # Permissive for testing
    ],
    'TEST_REQUEST_DEFAULT_FORMAT': 'json',
})

# Use test-specific REST framework settings
REST_FRAMEWORK = REST_FRAMEWORK_TEST

# API Documentation settings for testing
SPECTACULAR_SETTINGS.update({
    'SERVE_INCLUDE_SCHEMA': True,
    'SERVE_PERMISSIONS': ['rest_framework.permissions.AllowAny'],
})

print("Testing settings loaded successfully")