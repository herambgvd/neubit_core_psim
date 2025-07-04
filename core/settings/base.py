"""
Base Django settings for Neubit PSIM Core Platform Service.

This module contains the base configuration that is shared across all environments.
Environment-specific settings are defined in separate modules that import from this base.

Key Features:
- Microservice-ready architecture
- Production-grade security settings
- Comprehensive logging configuration
- Health monitoring setup
- Service integration framework
"""

import os
from pathlib import Path

import environ
import structlog

try:
    import pythonjsonlogger.jsonlogger
except ImportError:
    # Fallback if pythonjsonlogger is not installed
    pythonjsonlogger = None

# Build paths inside the project like this: BASE_DIR / 'subdir'.
BASE_DIR = Path(__file__).resolve().parent.parent.parent
ROOT_DIR = BASE_DIR.parent

# Environment configuration
env = environ.Env(
    DEBUG=(bool, False),
    SECRET_KEY=(str, ''),
    DATABASE_URL=(str, ''),
    REDIS_URL=(str, 'redis://localhost:6379/1'),
    CELERY_BROKER_URL=(str, 'redis://localhost:6379/2'),
    ALLOWED_HOSTS=(list, []),
    CORS_ALLOWED_ORIGINS=(list, []),
)

# Take environment variables from .env file if it exists
environ.Env.read_env(BASE_DIR / '.env')

# SECURITY WARNING: keep the secret key used in production secret!
SECRET_KEY = env('SECRET_KEY')

# SECURITY WARNING: don't run with debug turned on in production!
DEBUG = env('DEBUG')

# Application definition
DJANGO_APPS = [
    'django.contrib.admin',
    'django.contrib.auth',
    'django.contrib.contenttypes',
    'django.contrib.sessions',
    'django.contrib.messages',
    'django.contrib.staticfiles',
]

THIRD_PARTY_APPS = [
    'rest_framework',
    'corsheaders',
    'health_check',
    'health_check.db',
    'health_check.cache',
    'health_check.storage',
    'health_check.contrib.migrations',
    'health_check.contrib.redis',
    'health_check.contrib.celery',
    'drf_spectacular',
    'django_extensions',
]

LOCAL_APPS = [
    'apps.shared',
    'apps.authentication.apps.AuthenticationConfig',
    'apps.users.apps.UsersConfig',
    'apps.locations.apps.LocationsConfig',
    'apps.audit.apps.AuditConfig',
]

INSTALLED_APPS = DJANGO_APPS + THIRD_PARTY_APPS + LOCAL_APPS

# Middleware configuration for microservice architecture
MIDDLEWARE = [
    'corsheaders.middleware.CorsMiddleware',
    'django.middleware.security.SecurityMiddleware',
    'django.contrib.sessions.middleware.SessionMiddleware',
    'django.middleware.common.CommonMiddleware',
    'django.middleware.csrf.CsrfViewMiddleware',
    'django.contrib.auth.middleware.AuthenticationMiddleware',
    'django.contrib.messages.middleware.MessageMiddleware',
    'django.middleware.clickjacking.XFrameOptionsMiddleware',
    'apps.shared.middleware.RequestCorrelationMiddleware',
    'apps.shared.middleware.ServiceAuthenticationMiddleware',
    'apps.shared.middleware.PerformanceLoggingMiddleware',
]

ROOT_URLCONF = 'core.urls'

TEMPLATES = [
    {
        'BACKEND': 'django.template.backends.django.DjangoTemplates',
        'DIRS': [BASE_DIR / 'templates'],
        'APP_DIRS': True,
        'OPTIONS': {
            'context_processors': [
                'django.template.context_processors.debug',
                'django.template.context_processors.request',
                'django.contrib.auth.context_processors.auth',
                'django.contrib.messages.context_processors.messages',
            ],
        },
    },
]

WSGI_APPLICATION = 'core.wsgi.application'

# Database configuration with connection pooling
DATABASES = {
    'default': {
        **env.db(),
        'ENGINE': 'django_db_connection_pool.backends.postgresql',
        'POOL_OPTIONS': {
            'POOL_SIZE': 20,
            'MAX_OVERFLOW': 30,
            'RECYCLE': 24 * 60 * 60,  # 24 hours
        },
        'OPTIONS': {
            'MAX_CONNS': 50,
            'MIN_CONNS': 5,
        }
    }
}

# Internationalization
LANGUAGE_CODE = 'en-us'
TIME_ZONE = 'Asia/Kolkata'
USE_I18N = True
USE_TZ = True

# Static files (CSS, JavaScript, Images)
STATIC_URL = '/static/'
STATIC_ROOT = BASE_DIR / 'staticfiles'
STATICFILES_DIRS = [BASE_DIR / 'static']

# Media files
MEDIA_URL = '/media/'
MEDIA_ROOT = BASE_DIR / 'media'

# Default primary key field type
DEFAULT_AUTO_FIELD = 'django.db.models.BigAutoField'

# Custom user model
AUTH_USER_MODEL = 'users.User'

# User account settings
USER_ACCOUNT_SETTINGS = {
    'MAX_LOGIN_ATTEMPTS': 5,
    'ACCOUNT_LOCK_DURATION': 30,  # minutes
    'PASSWORD_EXPIRY_DAYS': 90,
    'PASSWORD_HISTORY_COUNT': 5,
    'FORCE_PASSWORD_CHANGE_ON_FIRST_LOGIN': True,
}

# Django REST Framework configuration
REST_FRAMEWORK = {
    'DEFAULT_AUTHENTICATION_CLASSES': [
        'apps.authentication.backends.JWTAuthentication',
        'rest_framework.authentication.SessionAuthentication',
    ],
    'DEFAULT_PERMISSION_CLASSES': [
        'rest_framework.permissions.IsAuthenticated',
    ],
    'DEFAULT_RENDERER_CLASSES': [
        'rest_framework.renderers.JSONRenderer',
        'rest_framework.renderers.BrowsableAPIRenderer',
    ],
    'DEFAULT_PARSER_CLASSES': [
        'rest_framework.parsers.JSONParser',
        'rest_framework.parsers.FormParser',
        'rest_framework.parsers.MultiPartParser',
    ],
    'DEFAULT_PAGINATION_CLASS': 'apps.shared.pagination.StandardResultsSetPagination',
    'PAGE_SIZE': 20,
    'DEFAULT_FILTER_BACKENDS': [
        'django_filters.rest_framework.DjangoFilterBackend',
        'rest_framework.filters.SearchFilter',
        'rest_framework.filters.OrderingFilter',
    ],
    'DEFAULT_SCHEMA_CLASS': 'drf_spectacular.openapi.AutoSchema',
    'EXCEPTION_HANDLER': 'apps.shared.exceptions.custom_exception_handler',
    # Throttling configuration - disable for development to avoid cache issues
    'DEFAULT_THROTTLE_CLASSES': [
        'rest_framework.throttling.AnonRateThrottle',
        'rest_framework.throttling.UserRateThrottle'
    ] if not DEBUG else [],  # Disable throttling in development
    'DEFAULT_THROTTLE_RATES': {
        'anon': '100/hour',
        'user': '1000/hour',
        'login': '10/minute',
    } if not DEBUG else {},  # Empty rates in development
    # Versioning
    'DEFAULT_VERSIONING_CLASS': 'rest_framework.versioning.URLPathVersioning',
    'DEFAULT_VERSION': 'v1',
    'ALLOWED_VERSIONS': ['v1'],
    'VERSION_PARAM': 'version',
    # Error handling
    'NON_FIELD_ERRORS_KEY': 'errors',
    'ORDERING_PARAM': 'ordering',
    'SEARCH_PARAM': 'search',
}

# Authentication backends
AUTHENTICATION_BACKENDS = [
    'apps.authentication.backends.CustomUserBackend',
    'django.contrib.auth.backends.ModelBackend',
]

# API Documentation with Spectacular
SPECTACULAR_SETTINGS = {
    'TITLE': 'Core Platform API',
    'DESCRIPTION': 'Central authentication, authorization, and location management service for PSIM ecosystem',
    'VERSION': '1.1.0',
    'SERVE_INCLUDE_SCHEMA': DEBUG,
    'SCHEMA_PATH_PREFIX': '/api/v1/',
    'COMPONENT_SPLIT_REQUEST': True,
    'SORT_OPERATIONS': False,
    'SWAGGER_UI_SETTINGS': {
        'deepLinking': True,
        'persistAuthorization': True,
        'displayOperationId': True,
    },
    'SERVE_PERMISSIONS': ['rest_framework.permissions.IsAuthenticated'],
    'TAGS': [
        {'name': 'Authentication', 'description': 'User authentication endpoints'},
        {'name': 'User Management', 'description': 'User management operations'},
        {'name': 'Role Management', 'description': 'RBAC role management'},
        {'name': 'Permission Management', 'description': 'Permission and access control'},
        {'name': 'Service Authentication', 'description': 'Service-to-service authentication'},
        {'name': 'Audit & Logging', 'description': 'Audit logs and monitoring'},
        {'name': 'Session Management', 'description': 'User session management'},
    ]
}

# Cache configuration with Redis
CACHES = {
    'default': {
        'BACKEND': 'django_redis.cache.RedisCache',
        'LOCATION': env('REDIS_URL', default='redis://localhost:6379/1'),
        'OPTIONS': {
            'CLIENT_CLASS': 'django_redis.client.DefaultClient',
            'PARSER_CLASS': 'redis.connection.PythonParser',  # Use PythonParser instead of HiredisParser
            'CONNECTION_POOL_KWARGS': {
                'max_connections': 50,
                'retry_on_timeout': True,
            },
            'SERIALIZER': 'django_redis.serializers.json.JSONSerializer',
            'COMPRESSOR': 'django_redis.compressors.zlib.ZlibCompressor',
        },
        'KEY_PREFIX': 'neubit_core',
        'TIMEOUT': 300,  # 5 minutes default timeout
    },
    'sessions': {
        'BACKEND': 'django_redis.cache.RedisCache',
        'LOCATION': env('REDIS_URL', default='redis://localhost:6379/2'),
        'OPTIONS': {
            'CLIENT_CLASS': 'django_redis.client.DefaultClient',
            'PARSER_CLASS': 'redis.connection.PythonParser',  # Use PythonParser instead of HiredisParser
            'CONNECTION_POOL_KWARGS': {
                'max_connections': 50,
                'retry_on_timeout': True,
            },
        },
        'KEY_PREFIX': 'neubit_sessions',
        'TIMEOUT': 86400,  # 24 hours for sessions
    }
}

# Session configuration
SESSION_ENGINE = 'django.contrib.sessions.backends.cache'
SESSION_CACHE_ALIAS = 'default'
SESSION_COOKIE_AGE = 86400  # 24 hours
SESSION_COOKIE_HTTPONLY = True
SESSION_COOKIE_SECURE = not DEBUG
SESSION_COOKIE_SAMESITE = 'Lax'

# Celery configuration for distributed task processing
CELERY_BROKER_URL = env('CELERY_BROKER_URL')
CELERY_RESULT_BACKEND = env('REDIS_URL')
CELERY_ACCEPT_CONTENT = ['json']
CELERY_TASK_SERIALIZER = 'json'
CELERY_RESULT_SERIALIZER = 'json'
CELERY_TIMEZONE = TIME_ZONE
CELERY_ENABLE_UTC = True
CELERY_TASK_TRACK_STARTED = True
CELERY_TASK_TIME_LIMIT = 30 * 60  # 30 minutes
CELERY_TASK_SOFT_TIME_LIMIT = 60  # 1 minute
CELERY_WORKER_PREFETCH_MULTIPLIER = 1
CELERY_WORKER_MAX_TASKS_PER_CHILD = 1000

# JWT Configuration
JWT_SETTINGS = {
    'ALGORITHM': 'HS256',
    'ACCESS_TOKEN_LIFETIME': 15 * 60,  # 15 minutes
    'REFRESH_TOKEN_LIFETIME': 7 * 24 * 60 * 60,  # 7 days
    'SERVICE_TOKEN_LIFETIME': 24 * 60 * 60,  # 24 hours
    'ROTATE_REFRESH_TOKENS': True,
    'BLACKLIST_AFTER_ROTATION': True,
    'ISSUER': 'neubit-psim-core',
    'AUDIENCE': 'neubit-psim-services',
}

# Security settings
SECURE_BROWSER_XSS_FILTER = True
SECURE_CONTENT_TYPE_NOSNIFF = True
X_FRAME_OPTIONS = 'DENY'
SECURE_HSTS_SECONDS = 31536000 if not DEBUG else 0
SECURE_HSTS_INCLUDE_SUBDOMAINS = True
SECURE_HSTS_PRELOAD = True

# CORS configuration for microservice communication
CORS_ALLOW_CREDENTIALS = True
CORS_ALLOWED_ORIGINS = env('CORS_ALLOWED_ORIGINS')
CORS_ALLOW_ALL_ORIGINS = DEBUG  # Only for development

# Service discovery and registration
SERVICE_DISCOVERY = {
    'SERVICE_NAME': 'Core Platform',
    'SERVICE_VERSION': '1.0.0',
    'SERVICE_DESCRIPTION': 'Core Platform Service',
    'HEALTH_CHECK_URL': '/health/',
    'KONG_ADMIN_URL': env('KONG_ADMIN_URL', default='http://localhost:8001'),
    'SERVICE_URL': env('SERVICE_URL', default='http://localhost:8000'),
}

# Audit and logging configuration
AUDIT_SETTINGS = {
    'ENABLE_AUDIT_LOG': True,
    'AUDIT_LOG_RETENTION_DAYS': 365,
    'SENSITIVE_FIELDS': ['password', 'token', 'secret'],
    'AUDIT_LOG_LEVEL': 'INFO',
}

# File upload settings
FILE_UPLOAD_MAX_MEMORY_SIZE = 10 * 1024 * 1024  # 10MB
DATA_UPLOAD_MAX_MEMORY_SIZE = 10 * 1024 * 1024  # 10MB
FILE_UPLOAD_PERMISSIONS = 0o644

# Rate limiting configuration
RATELIMIT_ENABLE = True
RATELIMIT_USE_CACHE = 'default'

# Health check configuration
HEALTH_CHECK = {
    'DISK_USAGE_MAX': 90,  # percent
    'MEMORY_MIN': 100,  # MB
}

# Configure structured logging
structlog.configure(
    processors=[
        structlog.stdlib.filter_by_level,
        structlog.stdlib.add_logger_name,
        structlog.stdlib.add_log_level,
        structlog.stdlib.PositionalArgumentsFormatter(),
        structlog.processors.TimeStamper(fmt="iso"),
        structlog.processors.StackInfoRenderer(),
        structlog.processors.format_exc_info,
        structlog.processors.UnicodeDecoder(),
        structlog.processors.JSONRenderer()
    ],
    context_class=dict,
    logger_factory=structlog.stdlib.LoggerFactory(),
    wrapper_class=structlog.stdlib.BoundLogger,
    cache_logger_on_first_use=True,
)

# Logging configuration
LOGGING = {
    'version': 1,
    'disable_existing_loggers': False,
    'formatters': {
        'verbose': {
            'format': '{levelname} {asctime} {module} {process:d} {thread:d} {message}',
            'style': '{',
        },
        'simple': {
            'format': '{levelname} {message}',
            'style': '{',
        },
        'json': {
            '()': 'pythonjsonlogger.jsonlogger.JsonFormatter',
            'format': '%(asctime)s %(name)s %(levelname)s %(message)s'
        } if pythonjsonlogger else {
            'format': '{levelname} {asctime} {name} {message}',
            'style': '{',
        },
    },
    'handlers': {
        'console': {
            'class': 'logging.StreamHandler',
            'formatter': 'json' if pythonjsonlogger else 'verbose',
        },
        'file': {
            'class': 'logging.handlers.RotatingFileHandler',
            'filename': os.path.join(BASE_DIR.parent, 'logs', 'core_platform.log'),
            'maxBytes': 1024 * 1024 * 15,  # 15MB
            'backupCount': 10,
            'formatter': 'json' if pythonjsonlogger else 'verbose',
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
            'handlers': ['console', 'file'],
            'level': 'DEBUG' if DEBUG else 'INFO',
            'propagate': False,
        },
        'apps': {
            'handlers': ['console', 'file'],
            'level': 'DEBUG' if DEBUG else 'INFO',
            'propagate': False,
        },
    },
}

# Logs Directory
logs_dir = BASE_DIR.parent / 'logs'
logs_dir.mkdir(exist_ok=True)

# Add avatar upload path
AVATAR_UPLOAD_PATH = 'avatars/%Y/%m/%d/'

# RBAC Settings
RBAC_SETTINGS = {
    'ENABLE_ROLE_HIERARCHY': True,
    'ENABLE_CONTEXT_PERMISSIONS': True,
    'DEFAULT_ROLE_EXPIRY_DAYS': None,  # No expiry by default
    'ENABLE_PERMISSION_REQUESTS': True,
    'AUTO_APPROVE_SIMPLE_REQUESTS': False,
}

# Audit settings for authentication
AUDIT_SETTINGS.update({
    'LOG_LOGIN_ATTEMPTS': True,
    'LOG_PERMISSION_CHECKS': True,
    'LOG_ROLE_CHANGES': True,
    'LOG_PASSWORD_CHANGES': True,
})

# Email settings for notifications
EMAIL_TEMPLATES = {
    'PASSWORD_RESET': 'emails/password_reset.html',
    'ACCOUNT_LOCKED': 'emails/account_locked.html',
    'ROLE_ASSIGNED': 'emails/role_assigned.html',
    'PERMISSION_REQUEST': 'emails/permission_request.html',
}
