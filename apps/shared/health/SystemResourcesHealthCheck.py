from typing import Dict, Any

import psutil
import structlog
from django.conf import settings

from apps.shared.health.BaseHealthCheck import BaseHealthCheck, HealthStatus

# Configure structured logger
logger = structlog.get_logger(__name__)


class SystemResourcesHealthCheck(BaseHealthCheck):
    """Health check for system resources (CPU, memory, disk)."""

    def __init__(self):
        super().__init__("system_resources", critical=False)

    def check(self) -> Dict[str, Any]:
        """
        Check system resource utilization.

        Returns:
            System resources health check results
        """
        try:
            # Get resource utilization
            cpu_percent = psutil.cpu_percent(interval=1)
            memory = psutil.virtual_memory()
            disk = psutil.disk_usage('/')

            # Check resource thresholds
            resource_status = self._check_resource_thresholds(cpu_percent, memory, disk)

            details = {
                'cpu': {
                    'percent': round(cpu_percent, 2),
                    'count': psutil.cpu_count()
                },
                'memory': {
                    'percent': round(memory.percent, 2),
                    'available_gb': round(memory.available / (1024 ** 3), 2),
                    'total_gb': round(memory.total / (1024 ** 3), 2)
                },
                'disk': {
                    'percent': round(disk.percent, 2),
                    'free_gb': round(disk.free / (1024 ** 3), 2),
                    'total_gb': round(disk.total / (1024 ** 3), 2)
                },
                'thresholds': resource_status['thresholds']
            }

            return self._format_result(
                status=resource_status['status'],
                message=resource_status['message'],
                details=details
            )

        except Exception as e:
            logger.error("system_resources_health_check_failed", error=str(e))
            return self._format_result(
                status=HealthStatus.UNKNOWN,
                message=f"System resources check failed: {str(e)}",
                details={'error': str(e)}
            )

    def _check_resource_thresholds(self, cpu_percent: float, memory, disk) -> Dict[str, Any]:
        """
        Check if system resources exceed thresholds.

        Args:
            cpu_percent: CPU utilization percentage
            memory: Memory information object
            disk: Disk usage information object

        Returns:
            Resource status information
        """
        # Configurable thresholds
        cpu_warning = getattr(settings, 'HEALTH_CHECK_CPU_WARNING', 80)
        cpu_critical = getattr(settings, 'HEALTH_CHECK_CPU_CRITICAL', 95)
        memory_warning = getattr(settings, 'HEALTH_CHECK_MEMORY_WARNING', 80)
        memory_critical = getattr(settings, 'HEALTH_CHECK_MEMORY_CRITICAL', 95)
        disk_warning = getattr(settings, 'HEALTH_CHECK_DISK_WARNING', 80)
        disk_critical = getattr(settings, 'HEALTH_CHECK_DISK_CRITICAL', 90)

        # Check critical thresholds
        if (cpu_percent >= cpu_critical or
                memory.percent >= memory_critical or
                disk.percent >= disk_critical):
            status = HealthStatus.UNHEALTHY
            message = "System resources critically high"
        # Check warning thresholds
        elif (cpu_percent >= cpu_warning or
              memory.percent >= memory_warning or
              disk.percent >= disk_warning):
            status = HealthStatus.DEGRADED
            message = "System resources elevated"
        else:
            status = HealthStatus.HEALTHY
            message = "System resources normal"

        return {
            'status': status,
            'message': message,
            'thresholds': {
                'cpu': {'warning': cpu_warning, 'critical': cpu_critical},
                'memory': {'warning': memory_warning, 'critical': memory_critical},
                'disk': {'warning': disk_warning, 'critical': disk_critical}
            }
        }
