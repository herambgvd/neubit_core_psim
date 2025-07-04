"""
Main URL configuration for Neubit PSIM Core Platform Service.

This module defines the primary URL routing for the entire service,
including API endpoints, health checks, admin interface, and
documentation endpoints.

URL Structure:
- /admin/ - Django admin interface
- /api/v1/ - Main API endpoints
- /health/ - Health check endpoints
- /docs/ - API documentation
- /metrics/ - Monitoring metrics
"""

from django.contrib import admin
from django.urls import path, include
from django.conf import settings
from django.conf.urls.static import static
from django.http import JsonResponse
from django.views.decorators.csrf import csrf_exempt
from drf_spectacular.views import (
    SpectacularAPIView,
    SpectacularRedocView,
    SpectacularSwaggerView,
)


@csrf_exempt
def service_info(request):
    """
    Service information endpoint.

    Provides basic information about the service including
    version, name, and available endpoints.

    Args:
        request: HTTP request object

    Returns:
        JsonResponse with service information
    """
    service_config = getattr(settings, 'SERVICE_DISCOVERY', {})

    return JsonResponse({
        'service': service_config.get('SERVICE_NAME', 'core-platform'),
        'version': service_config.get('SERVICE_VERSION', '1.0.0'),
        'description': service_config.get('SERVICE_DESCRIPTION', 'Core Platform Service'),
        'status': 'running',
        'endpoints': {
            'health': '/health/',
            'api': '/api/v1/',
            'docs': '/api/docs/',
            'admin': '/admin/',
            'metrics': '/health/metrics/'
        },
        'api_version': 'v1'
    })


# Main URL patterns
urlpatterns = [
    # Service information endpoint
    path('', service_info, name='service_info'),

    # Django admin interface
    path('admin/', admin.site.urls),

    # Health check and shared services endpoints
    path('', include('apps.shared.urls.health')),

    # API v1 endpoints
    path('api/v1/', include([
        # Authentication endpoints
        path('auth/', include('apps.authentication.urls')),

        # User management endpoints
        path('users/', include('apps.users.urls')),

        # Location management endpoints
        path('locations/', include('apps.locations.urls')),

        # Audit endpoints
        path('audit/', include('apps.audit.urls')),
    ])),

    # API Documentation endpoints
    path('api/schema/', SpectacularAPIView.as_view(), name='schema'),
    path('api/docs/', SpectacularSwaggerView.as_view(url_name='schema'), name='swagger-ui'),
    path('api/redoc/', SpectacularRedocView.as_view(url_name='schema'), name='redoc'),
]

# Serve static and media files in development
if settings.DEBUG:
    urlpatterns += static(settings.STATIC_URL, document_root=settings.STATIC_ROOT)
    urlpatterns += static(settings.MEDIA_URL, document_root=settings.MEDIA_ROOT)

    # Add debug toolbar URLs in development
    if 'debug_toolbar' in settings.INSTALLED_APPS:
        import debug_toolbar
        urlpatterns = [
            path('__debug__/', include(debug_toolbar.urls)),
        ] + urlpatterns

# Configure Django admin
admin.site.site_header = 'Neubit PSIM Core Platform Administration'
admin.site.site_title = 'Neubit PSIM Admin'
admin.site.index_title = 'Core Platform Administration'