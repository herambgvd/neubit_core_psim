"""
Production settings for Neubit PSIM Core Platform Service.

This module contains settings specific to the production environment.
It inherits from base settings and overrides configurations for
production deployment with security and performance optimizations.
"""

import sentry_sdk
from sentry_sdk.integrations.celery import CeleryIntegration
from sentry_sdk.integrations.django import DjangoIntegration
from sentry_sdk.integrations.redis import RedisIntegration

from .base import *

# Production mode - Debug must be False
DEBUG = False

# Security: Require proper SECRET_KEY in production
if not SECRET_KEY or SECRET_KEY == 'dev-secret-key-change-in-production':
    raise ValueError("SECRET_KEY must be set to a secure value in production")

# Production allowed hosts - must be configured
ALLOWED_HOSTS = env.list('ALLOWED_HOSTS', default=[])
if not ALLOWED_HOSTS:
    raise ValueError("ALLOWED_HOSTS must be configured in production")

# Database configuration for production with optimizations
DATABASES = {
    'default': {
        **env.db(),
        'ENGINE': 'django_db_connection_pool.backends.postgresql',
        'CONN_MAX_AGE': 600,  # Connection persistence
        'POOL_OPTIONS': {
            'POOL_SIZE': 50,
            'MAX_OVERFLOW': 100,
            'RECYCLE': 3600,  # 1 hour
            'ECHO': False,
        },
        'OPTIONS': {
            'MAX_CONNS': 100,
            'MIN_CONNS': 10,
            'sslmode': 'require',  # Require SSL in production
        }
    }
}

# Redis configuration for production
CACHES = {
    'default': {
        'BACKEND': 'django_redis.cache.RedisCache',
        'LOCATION': env('REDIS_URL'),
        'OPTIONS': {
            'CLIENT_CLASS': 'django_redis.client.DefaultClient',
            'PARSER_CLASS': 'redis.connection.HiredisParser',
            'CONNECTION_POOL_KWARGS': {
                'max_connections': 100,
                'retry_on_timeout': True,
                'health_check_interval': 30,
            },
            'SERIALIZER': 'django_redis.serializers.json.JSONSerializer',
            'COMPRESSOR': 'django_redis.compressors.zlib.ZlibCompressor',
        },
        'KEY_PREFIX': 'neubit_core_prod',
        'TIMEOUT': 300,
        'VERSION': 1,
    }
}

# Production security settings
SECURE_SSL_REDIRECT = True
SECURE_PROXY_SSL_HEADER = ('HTTP_X_FORWARDED_PROTO', 'https')
SECURE_HSTS_SECONDS = 31536000  # 1 year
SECURE_HSTS_INCLUDE_SUBDOMAINS = True
SECURE_HSTS_PRELOAD = True
SECURE_CONTENT_TYPE_NOSNIFF = True
SECURE_BROWSER_XSS_FILTER = True
SECURE_REFERRER_POLICY = 'strict-origin-when-cross-origin'

# Session security
SESSION_COOKIE_SECURE = True
SESSION_COOKIE_HTTPONLY = True
SESSION_COOKIE_SAMESITE = 'Strict'
SESSION_COOKIE_AGE = 3600  # 1 hour

# CSRF security
CSRF_COOKIE_SECURE = True
CSRF_COOKIE_HTTPONLY = True
CSRF_COOKIE_SAMESITE = 'Strict'
CSRF_TRUSTED_ORIGINS = env.list('CSRF_TRUSTED_ORIGINS', default=[])

# Email configuration for production
EMAIL_BACKEND = 'django.core.mail.backends.smtp.EmailBackend'
EMAIL_HOST = env('EMAIL_HOST', default='localhost')
EMAIL_PORT = env('EMAIL_PORT', default=587, cast=int)
EMAIL_USE_TLS = env('EMAIL_USE_TLS', default=True, cast=bool)
EMAIL_HOST_USER = env('EMAIL_HOST_USER', default='')
EMAIL_HOST_PASSWORD = env('EMAIL_HOST_PASSWORD', default='')
DEFAULT_FROM_EMAIL = env('DEFAULT_FROM_EMAIL', default='noreply@neubit.com')

# Static files configuration for production
STATIC_ROOT = env('STATIC_ROOT', default=str(BASE_DIR / 'staticfiles'))
STATICFILES_STORAGE = 'django.contrib.staticfiles.storage.ManifestStaticFilesStorage'

# Media files configuration for production
MEDIA_ROOT = env('MEDIA_ROOT', default=str(BASE_DIR / 'media'))
DEFAULT_FILE_STORAGE = env('DEFAULT_FILE_STORAGE', default='django.core.files.storage.FileSystemStorage')

# Celery configuration for production
CELERY_BROKER_URL = env('CELERY_BROKER_URL')
CELERY_RESULT_BACKEND = env('REDIS_URL')
CELERY_WORKER_CONCURRENCY = env('CELERY_WORKER_CONCURRENCY', default=4, cast=int)
CELERY_WORKER_MAX_TASKS_PER_CHILD = 1000
CELERY_WORKER_PREFETCH_MULTIPLIER = 1
CELERY_TASK_ACKS_LATE = True
CELERY_TASK_REJECT_ON_WORKER_LOST = True

# Production logging configuration
LOGGING = {
    'version': 1,
    'disable_existing_loggers': False,
    'formatters': {
        'verbose': {
            'format': '{levelname} {asctime} {module} {process:d} {thread:d} {message}',
            'style': '{',
        },
        'json': {
            '()': 'pythonjsonlogger.jsonlogger.JsonFormatter',
            'format': '%(asctime)s %(name)s %(levelname)s %(message)s %(pathname)s %(lineno)d'
        },
    },
    'handlers': {
        'console': {
            'class': 'logging.StreamHandler',
            'formatter': 'json',
            'level': 'INFO',
        },
        'file': {
            'class': 'logging.handlers.RotatingFileHandler',
            'filename': env('LOG_FILE', default='/var/log/neubit/core_platform.log'),
            'maxBytes': 1024 * 1024 * 50,  # 50MB
            'backupCount': 20,
            'formatter': 'json',
            'level': 'INFO',
        },
        'error_file': {
            'class': 'logging.handlers.RotatingFileHandler',
            'filename': env('ERROR_LOG_FILE', default='/var/log/neubit/core_platform_error.log'),
            'maxBytes': 1024 * 1024 * 50,  # 50MB
            'backupCount': 10,
            'formatter': 'json',
            'level': 'ERROR',
        },
    },
    'root': {
        'handlers': ['console', 'file'],
        'level': 'INFO',
    },
    'loggers': {
        'django': {
            'handlers': ['console', 'file'],
            'level': 'INFO',
            'propagate': False,
        },
        'core': {
            'handlers': ['console', 'file', 'error_file'],
            'level': 'INFO',
            'propagate': False,
        },
        'apps': {
            'handlers': ['console', 'file', 'error_file'],
            'level': 'INFO',
            'propagate': False,
        },
        'celery': {
            'handlers': ['console', 'file'],
            'level': 'INFO',
            'propagate': False,
        },
    },
}

# Sentry configuration for error tracking
SENTRY_DSN = env('SENTRY_DSN', default='')
if SENTRY_DSN:
    sentry_sdk.init(
        dsn=SENTRY_DSN,
        integrations=[
            DjangoIntegration(),
            CeleryIntegration(),
            RedisIntegration(),
        ],
        traces_sample_rate=env('SENTRY_TRACES_SAMPLE_RATE', default=0.1, cast=float),
        send_default_pii=False,
        environment=env('ENVIRONMENT', default='production'),
        release=env('RELEASE_VERSION', default='1.0.0'),
    )

# Performance optimizations
CONN_MAX_AGE = 600  # Database connection persistence

# API rate limiting for production
RATELIMIT_ENABLE = True
REST_FRAMEWORK['DEFAULT_THROTTLE_CLASSES'] = [
    'rest_framework.throttling.AnonRateThrottle',
    'rest_framework.throttling.UserRateThrottle'
]
REST_FRAMEWORK['DEFAULT_THROTTLE_RATES'] = {
    'anon': env('API_RATE_LIMIT_ANON', default='100/hour'),
    'user': env('API_RATE_LIMIT_USER', default='1000/hour'),
}

# Production-specific middleware
MIDDLEWARE = [
                 'django.middleware.cache.UpdateCacheMiddleware',
             ] + MIDDLEWARE + [
                 'django.middleware.cache.FetchFromCacheMiddleware',
             ]

# Cache middleware settings
CACHE_MIDDLEWARE_ALIAS = 'default'
CACHE_MIDDLEWARE_SECONDS = 300
CACHE_MIDDLEWARE_KEY_PREFIX = 'neubit_core_prod'

# Service discovery for production
SERVICE_DISCOVERY.update({
    'KONG_ADMIN_URL': env('KONG_ADMIN_URL'),
    'SERVICE_URL': env('SERVICE_URL'),
    'ENVIRONMENT': 'production',
})

# Health check thresholds for production
HEALTH_CHECK.update({
    'DISK_USAGE_MAX': 85,
    'MEMORY_MIN': 500,  # Minimum 500MB available
})

# JWT settings for production
JWT_SETTINGS.update({
    'ACCESS_TOKEN_LIFETIME': 15 * 60,  # 15 minutes
    'REFRESH_TOKEN_LIFETIME': 24 * 60 * 60,  # 24 hours
    'ALGORITHM': 'RS256',  # Use RS256 for production
})

# File upload settings for production
FILE_UPLOAD_MAX_MEMORY_SIZE = 5 * 1024 * 1024  # 5MB
DATA_UPLOAD_MAX_MEMORY_SIZE = 5 * 1024 * 1024  # 5MB

# Admin configuration
ADMINS = env.list('ADMINS', default=[], cast=lambda x: [tuple(admin.split(':')) for admin in x])
MANAGERS = ADMINS

print("Production settings loaded successfully")
