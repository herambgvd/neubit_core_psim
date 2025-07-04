"""
URL configuration for shared services and health checks.

This module defines URL patterns for:
- Health check endpoints
- Metrics endpoints
- Service discovery endpoints
- Utility endpoints

All endpoints are designed to be consumed by monitoring tools,
load balancers, and other microservices.
"""

from django.urls import path, include
from apps.shared.views.health import (
    HealthCheckView,
    ReadinessCheckView,
    LivenessCheckView,
    ComponentHealthView,
    HealthMetricsView,
    simple_health_check
)

app_name = 'shared'

# Health check URL patterns
health_urlpatterns = [
    # Comprehensive health check endpoint
    path('health/', HealthCheckView.as_view(), name='health_check'),

    # Kubernetes/Docker health check endpoints
    path('health/ready/', ReadinessCheckView.as_view(), name='readiness_check'),
    path('health/live/', LivenessCheckView.as_view(), name='liveness_check'),

    # Simple health check for basic monitoring
    path('health/simple/', simple_health_check, name='simple_health_check'),

    # Component-specific health checks
    path('health/component/<str:component_name>/', ComponentHealthView.as_view(), name='component_health'),

    # Health metrics for monitoring systems
    path('health/metrics/', HealthMetricsView.as_view(), name='health_metrics'),
]

# Main URL patterns
urlpatterns = [
    # Include health check URLs at root level
    path('', include(health_urlpatterns)),

    # Legacy health endpoint (for backward compatibility)
    path('status/', simple_health_check, name='legacy_status'),

    # Ping endpoint for simple availability check
    path('ping/', simple_health_check, name='ping'),
]