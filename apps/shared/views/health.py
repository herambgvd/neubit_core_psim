"""
Health check API views for Neubit PSIM Core Platform Service.

This module provides REST API endpoints for health monitoring:
- Comprehensive health status
- Readiness checks for load balancers
- Liveness checks for container orchestration
- Individual component health checks
- Health metrics for monitoring systems

All endpoints are designed to be consumed by monitoring tools,
load balancers, and container orchestration platforms.
"""

import structlog
from django.http import JsonResponse
from django.utils.decorators import method_decorator
from django.views.decorators.cache import never_cache
from django.views.decorators.csrf import csrf_exempt
from django.views.decorators.http import require_http_methods
from rest_framework import status
from rest_framework.permissions import AllowAny
from rest_framework.response import Response
from rest_framework.views import APIView

from apps.shared.health.BaseHealthCheck import HealthStatus
from apps.shared.health.ServiceHealthManager import health_manager

# Configure structured logger
logger = structlog.get_logger(__name__)


@method_decorator([csrf_exempt, never_cache], name='dispatch')
class HealthCheckView(APIView):
    """
    Comprehensive health check endpoint.

    This endpoint provides detailed health information about all
    service components including databases, caches, queues, and
    system resources.

    Response includes:
    - Overall service health status
    - Individual component statuses
    - Performance metrics
    - Diagnostic information
    """

    permission_classes = [AllowAny]

    def get(self, request):
        """
        Get comprehensive health status.

        Query Parameters:
            include_details (bool): Include detailed diagnostic information
            include_non_critical (bool): Include non-critical component checks

        Returns:
            JSON response with comprehensive health status
        """
        # Parse query parameters
        include_details = request.GET.get('include_details', 'true').lower() == 'true'
        include_non_critical = request.GET.get('include_non_critical', 'true').lower() == 'true'

        try:
            # Get comprehensive health status
            health_data = health_manager.check_all(include_non_critical=include_non_critical)

            # Remove detailed information if not requested
            if not include_details:
                for check in health_data.get('checks', []):
                    check.pop('details', None)

            # Determine HTTP status code based on health
            http_status = self._get_http_status(health_data['status'])

            # Log health check request
            logger.info(
                "health_check_requested",
                correlation_id=getattr(request, 'correlation_id', ''),
                overall_status=health_data['status'],
                include_details=include_details,
                include_non_critical=include_non_critical,
                component_count=len(health_data.get('checks', []))
            )

            return Response(health_data, status=http_status)

        except Exception as e:
            logger.error(
                "health_check_error",
                correlation_id=getattr(request, 'correlation_id', ''),
                error=str(e)
            )

            error_response = {
                'status': HealthStatus.UNKNOWN,
                'message': f'Health check failed: {str(e)}',
                'error': str(e)
            }

            return Response(error_response, status=status.HTTP_503_SERVICE_UNAVAILABLE)

    def _get_http_status(self, health_status: str) -> int:
        """
        Convert health status to appropriate HTTP status code.

        Args:
            health_status: Health status string

        Returns:
            HTTP status code
        """
        status_mapping = {
            HealthStatus.HEALTHY: status.HTTP_200_OK,
            HealthStatus.DEGRADED: status.HTTP_200_OK,  # Still functional
            HealthStatus.UNHEALTHY: status.HTTP_503_SERVICE_UNAVAILABLE,
            HealthStatus.UNKNOWN: status.HTTP_503_SERVICE_UNAVAILABLE
        }

        return status_mapping.get(health_status, status.HTTP_503_SERVICE_UNAVAILABLE)


@method_decorator([csrf_exempt, never_cache], name='dispatch')
class ReadinessCheckView(APIView):
    """
    Kubernetes/Docker readiness check endpoint.

    This endpoint is designed for container orchestration platforms
    to determine if the service is ready to receive traffic.

    Returns HTTP 200 if ready, HTTP 503 if not ready.
    """

    permission_classes = [AllowAny]

    def get(self, request):
        """
        Check if service is ready to receive traffic.

        Returns:
            JSON response with readiness status
        """
        try:
            readiness_data = health_manager.check_readiness()

            logger.info(
                "readiness_check_requested",
                correlation_id=getattr(request, 'correlation_id', ''),
                ready=readiness_data['ready']
            )

            if readiness_data['ready']:
                return Response(readiness_data, status=status.HTTP_200_OK)
            else:
                return Response(readiness_data, status=status.HTTP_503_SERVICE_UNAVAILABLE)

        except Exception as e:
            logger.error(
                "readiness_check_error",
                correlation_id=getattr(request, 'correlation_id', ''),
                error=str(e)
            )

            error_response = {
                'ready': False,
                'message': f'Readiness check failed: {str(e)}',
                'error': str(e)
            }

            return Response(error_response, status=status.HTTP_503_SERVICE_UNAVAILABLE)


@method_decorator([csrf_exempt, never_cache], name='dispatch')
class LivenessCheckView(APIView):
    """
    Kubernetes/Docker liveness check endpoint.

    This endpoint is designed for container orchestration platforms
    to determine if the service is alive and should be restarted
    if it becomes unresponsive.

    Returns HTTP 200 if alive, HTTP 503 if dead.
    """

    permission_classes = [AllowAny]

    def get(self, request):
        """
        Check if service is alive and responding.

        Returns:
            JSON response with liveness status
        """
        try:
            liveness_data = health_manager.check_liveness()

            logger.info(
                "liveness_check_requested",
                correlation_id=getattr(request, 'correlation_id', ''),
                alive=liveness_data['alive']
            )

            if liveness_data['alive']:
                return Response(liveness_data, status=status.HTTP_200_OK)
            else:
                return Response(liveness_data, status=status.HTTP_503_SERVICE_UNAVAILABLE)

        except Exception as e:
            logger.error(
                "liveness_check_error",
                correlation_id=getattr(request, 'correlation_id', ''),
                error=str(e)
            )

            error_response = {
                'alive': False,
                'message': f'Liveness check failed: {str(e)}',
                'error': str(e)
            }

            return Response(error_response, status=status.HTTP_503_SERVICE_UNAVAILABLE)


@require_http_methods(["GET"])
@csrf_exempt
@never_cache
def simple_health_check(request):
    """
    Simple health check endpoint for basic monitoring.

    This is a lightweight endpoint that returns a simple
    JSON response indicating service availability.

    Args:
        request: HTTP request object

    Returns:
        JsonResponse with basic health status
    """
    try:
        # Perform minimal health check
        liveness_data = health_manager.check_liveness()

        if liveness_data['alive']:
            response_data = {
                'status': 'ok',
                'service': 'neubit-psim-core',
                'timestamp': liveness_data['timestamp']
            }
            return JsonResponse(response_data, status=200)
        else:
            response_data = {
                'status': 'error',
                'service': 'neubit-psim-core',
                'message': liveness_data.get('message', 'Service not available')
            }
            return JsonResponse(response_data, status=503)

    except Exception as e:
        response_data = {
            'status': 'error',
            'service': 'neubit-psim-core',
            'message': f'Health check failed: {str(e)}'
        }
        return JsonResponse(response_data, status=503)


@method_decorator([csrf_exempt, never_cache], name='dispatch')
class ComponentHealthView(APIView):
    """
    Individual component health check endpoint.

    This endpoint allows checking the health of specific
    system components individually.
    """

    permission_classes = [AllowAny]

    def get(self, request, component_name):
        """
        Get health status for a specific component.

        Args:
            component_name: Name of the component to check

        Returns:
            JSON response with component health status
        """
        try:
            # Get all health checks
            all_checks = health_manager.check_all()

            # Find the requested component
            component_result = None
            for check in all_checks.get('checks', []):
                if check['name'] == component_name:
                    component_result = check
                    break

            if not component_result:
                return Response(
                    {
                        'error': f'Component "{component_name}" not found',
                        'available_components': [
                            check['name'] for check in all_checks.get('checks', [])
                        ]
                    },
                    status=status.HTTP_404_NOT_FOUND
                )

            # Determine HTTP status based on component health
            if component_result['status'] == HealthStatus.UNHEALTHY:
                http_status = status.HTTP_503_SERVICE_UNAVAILABLE
            else:
                http_status = status.HTTP_200_OK

            logger.info(
                "component_health_check_requested",
                correlation_id=getattr(request, 'correlation_id', ''),
                component=component_name,
                status=component_result['status']
            )

            return Response(component_result, status=http_status)

        except Exception as e:
            logger.error(
                "component_health_check_error",
                correlation_id=getattr(request, 'correlation_id', ''),
                component=component_name,
                error=str(e)
            )

            error_response = {
                'error': f'Component health check failed: {str(e)}',
                'component': component_name
            }

            return Response(error_response, status=status.HTTP_503_SERVICE_UNAVAILABLE)


@method_decorator([csrf_exempt, never_cache], name='dispatch')
class HealthMetricsView(APIView):
    """
    Health metrics endpoint for monitoring systems.

    This endpoint provides health metrics in a format suitable
    for monitoring systems like Prometheus, Grafana, etc.
    """

    permission_classes = [AllowAny]

    def get(self, request):
        """
        Get health metrics for monitoring systems.

        Returns:
            JSON response with health metrics
        """
        try:
            # Get comprehensive health data
            health_data = health_manager.check_all()

            # Convert to metrics format
            metrics = self._convert_to_metrics(health_data)

            logger.info(
                "health_metrics_requested",
                correlation_id=getattr(request, 'correlation_id', ''),
                metric_count=len(metrics)
            )

            return Response({
                'metrics': metrics,
                'timestamp': health_data['timestamp'],
                'service': health_data['service']
            }, status=status.HTTP_200_OK)

        except Exception as e:
            logger.error(
                "health_metrics_error",
                correlation_id=getattr(request, 'correlation_id', ''),
                error=str(e)
            )

            return Response(
                {'error': f'Health metrics failed: {str(e)}'},
                status=status.HTTP_503_SERVICE_UNAVAILABLE
            )

    def _convert_to_metrics(self, health_data: dict) -> list:
        """
        Convert health data to metrics format.

        Args:
            health_data: Health check results

        Returns:
            List of metrics
        """
        metrics = []

        # Overall service health metric
        overall_status_value = self._status_to_value(health_data['status'])
        metrics.append({
            'name': 'service_health_status',
            'value': overall_status_value,
            'labels': {
                'service': health_data['service']['name'],
                'version': health_data['service']['version']
            },
            'help': 'Overall service health status (1=healthy, 0.5=degraded, 0=unhealthy)'
        })

        # Component health metrics
        for check in health_data.get('checks', []):
            component_status_value = self._status_to_value(check['status'])
            metrics.append({
                'name': 'component_health_status',
                'value': component_status_value,
                'labels': {
                    'component': check['name'],
                    'critical': str(check['critical']).lower()
                },
                'help': 'Component health status (1=healthy, 0.5=degraded, 0=unhealthy)'
            })

            # Add specific metrics if available
            if 'details' in check:
                self._add_component_metrics(metrics, check)

        # Health check duration metric
        metrics.append({
            'name': 'health_check_duration_ms',
            'value': health_data['duration_ms'],
            'labels': {},
            'help': 'Time taken to complete health checks in milliseconds'
        })

        return metrics

    def _status_to_value(self, status: str) -> float:
        """
        Convert health status to numeric value.

        Args:
            status: Health status string

        Returns:
            Numeric value representing status
        """
        status_values = {
            HealthStatus.HEALTHY: 1.0,
            HealthStatus.DEGRADED: 0.5,
            HealthStatus.UNHEALTHY: 0.0,
            HealthStatus.UNKNOWN: -1.0
        }

        return status_values.get(status, -1.0)

    def _add_component_metrics(self, metrics: list, check: dict) -> None:
        """
        Add component-specific metrics to the metrics list.

        Args:
            metrics: List of metrics to append to
            check: Component health check result
        """
        details = check.get('details', {})
        component_name = check['name']

        # Database metrics
        if component_name == 'database' and 'query_time_ms' in details:
            metrics.append({
                'name': 'database_query_time_ms',
                'value': details['query_time_ms'],
                'labels': {'component': 'database'},
                'help': 'Database query response time in milliseconds'
            })

        # Cache metrics
        if component_name == 'cache' and 'operation_time_ms' in details:
            metrics.append({
                'name': 'cache_operation_time_ms',
                'value': details['operation_time_ms'],
                'labels': {'component': 'cache'},
                'help': 'Cache operation response time in milliseconds'
            })

        # System resource metrics
        if component_name == 'system_resources':
            if 'cpu' in details:
                metrics.append({
                    'name': 'system_cpu_percent',
                    'value': details['cpu']['percent'],
                    'labels': {},
                    'help': 'System CPU utilization percentage'
                })

            if 'memory' in details:
                metrics.append({
                    'name': 'system_memory_percent',
                    'value': details['memory']['percent'],
                    'labels': {},
                    'help': 'System memory utilization percentage'
                })

                metrics.append({
                    'name': 'system_memory_available_gb',
                    'value': details['memory']['available_gb'],
                    'labels': {},
                    'help': 'System available memory in GB'
                })

            if 'disk' in details:
                metrics.append({
                    'name': 'system_disk_percent',
                    'value': details['disk']['percent'],
                    'labels': {},
                    'help': 'System disk utilization percentage'
                })

        # Celery metrics
        if component_name == 'celery' and 'worker_count' in details:
            metrics.append({
                'name': 'celery_worker_count',
                'value': details['worker_count'],
                'labels': {},
                'help': 'Number of active Celery workers'
            })
