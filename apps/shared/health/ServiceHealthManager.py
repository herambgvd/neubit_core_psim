import time
import time
from datetime import datetime
from typing import Dict, Any

import psutil
import structlog
from django.conf import settings
from apps.shared.health.BaseHealthCheck import HealthStatus
from apps.shared.health.DatabaseHealthCheck import DatabaseHealthCheck
from apps.shared.health.CeleryHealthCheck import CeleryHealthCheck
from apps.shared.health.CacheHealthCheck import CacheHealthCheck
from apps.shared.health.SystemResourcesHealthCheck import SystemResourcesHealthCheck

# Configure structured logger
logger = structlog.get_logger(__name__)


class ServiceHealthManager:
    """
    Manager class for coordinating all health checks.

    This class orchestrates multiple health check components and
    provides comprehensive service health status.
    """

    def __init__(self):
        """Initialize health check manager with all components."""
        self.health_checks = [
            DatabaseHealthCheck(),
            CacheHealthCheck(),
            CeleryHealthCheck(),
            SystemResourcesHealthCheck(),
        ]

    def check_all(self, include_non_critical: bool = True) -> Dict[str, Any]:
        """
        Run all health checks and return comprehensive status.

        Args:
            include_non_critical: Whether to include non-critical checks

        Returns:
            Comprehensive health check results
        """
        start_time = time.time()
        results = []
        overall_status = HealthStatus.HEALTHY

        for health_check in self.health_checks:
            # Skip non-critical checks if requested
            if not include_non_critical and not health_check.critical:
                continue

            try:
                result = health_check.check()
                results.append(result)

                # Update overall status based on critical components
                if health_check.critical:
                    if result['status'] == HealthStatus.UNHEALTHY:
                        overall_status = HealthStatus.UNHEALTHY
                    elif (result['status'] == HealthStatus.DEGRADED and
                          overall_status != HealthStatus.UNHEALTHY):
                        overall_status = HealthStatus.DEGRADED

            except Exception as e:
                logger.error(
                    "health_check_component_failed",
                    component=health_check.name,
                    error=str(e)
                )

                error_result = {
                    'name': health_check.name,
                    'status': HealthStatus.UNKNOWN,
                    'message': f"Health check failed: {str(e)}",
                    'critical': health_check.critical,
                    'timestamp': datetime.utcnow().isoformat(),
                    'error': str(e)
                }
                results.append(error_result)

                # Mark overall status as unhealthy if critical component fails
                if health_check.critical:
                    overall_status = HealthStatus.UNHEALTHY

        check_duration = (time.time() - start_time) * 1000

        return {
            'status': overall_status,
            'timestamp': datetime.utcnow().isoformat(),
            'duration_ms': round(check_duration, 2),
            'service': {
                'name': getattr(settings, 'SERVICE_DISCOVERY', {}).get('SERVICE_NAME', 'core-platform'),
                'version': getattr(settings, 'SERVICE_DISCOVERY', {}).get('SERVICE_VERSION', '1.0.0'),
            },
            'checks': results
        }

    def check_readiness(self) -> Dict[str, Any]:
        """
        Check if service is ready to receive traffic.

        Returns:
            Readiness check results
        """
        # Only check critical components for readiness
        critical_checks = [hc for hc in self.health_checks if hc.critical]

        results = []
        is_ready = True

        for health_check in critical_checks:
            try:
                result = health_check.check()
                results.append(result)

                if result['status'] == HealthStatus.UNHEALTHY:
                    is_ready = False

            except Exception as e:
                logger.error(
                    "readiness_check_failed",
                    component=health_check.name,
                    error=str(e)
                )
                is_ready = False

        return {
            'ready': is_ready,
            'timestamp': datetime.utcnow().isoformat(),
            'checks': results
        }

    def check_liveness(self) -> Dict[str, Any]:
        """
        Check if service is alive and responding.

        Returns:
            Liveness check results
        """
        # Simple liveness check - just verify basic functionality
        try:
            # Test basic database connectivity
            from django.db import connection
            with connection.cursor() as cursor:
                cursor.execute("SELECT 1")

            return {
                'alive': True,
                'timestamp': datetime.utcnow().isoformat(),
                'message': "Service is alive"
            }

        except Exception as e:
            logger.error("liveness_check_failed", error=str(e))
            return {
                'alive': False,
                'timestamp': datetime.utcnow().isoformat(),
                'message': f"Service liveness check failed: {str(e)}",
                'error': str(e)
            }


# Global health manager instance
health_manager = ServiceHealthManager()
