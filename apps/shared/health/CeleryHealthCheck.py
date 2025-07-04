from typing import Dict, List, Any, Optional

import psutil
import structlog
from celery import current_app as celery_app
from django.conf import settings
from apps.shared.health.BaseHealthCheck import BaseHealthCheck, HealthStatus

# Configure structured logger
logger = structlog.get_logger(__name__)


class CeleryHealthCheck(BaseHealthCheck):
    """Health check for Celery task queue system."""

    def __init__(self):
        super().__init__("celery", critical=False)

    def check(self) -> Dict[str, Any]:
        """
        Check Celery health and worker status.

        Returns:
            Celery health check results
        """
        try:
            # Check if Celery is configured
            if not hasattr(settings, 'CELERY_BROKER_URL'):
                return self._format_result(
                    status=HealthStatus.UNKNOWN,
                    message="Celery is not configured"
                )

            # Get worker statistics
            inspector = celery_app.control.inspect()

            # Check active workers
            active_workers = inspector.active()
            worker_stats = inspector.stats()

            if not active_workers:
                return self._format_result(
                    status=HealthStatus.DEGRADED,
                    message="No active Celery workers found",
                    details={'workers': 0}
                )

            worker_count = len(active_workers)

            # Get detailed worker information
            worker_details = self._get_worker_details(active_workers, worker_stats)

            return self._format_result(
                status=HealthStatus.HEALTHY,
                message=f"Celery is healthy with {worker_count} active workers",
                details={
                    'worker_count': worker_count,
                    'workers': worker_details
                }
            )

        except Exception as e:
            logger.error("celery_health_check_failed", error=str(e))
            return self._format_result(
                status=HealthStatus.UNHEALTHY,
                message=f"Celery check failed: {str(e)}",
                details={'error': str(e)}
            )

    def _get_worker_details(self, active_workers: Dict, worker_stats: Optional[Dict]) -> List[Dict]:
        """
        Get detailed information about Celery workers.

        Args:
            active_workers: Active worker information
            worker_stats: Worker statistics

        Returns:
            List of worker details
        """
        workers = []

        for worker_name, tasks in active_workers.items():
            worker_info = {
                'name': worker_name,
                'active_tasks': len(tasks),
                'tasks': [task['name'] for task in tasks]
            }

            # Add statistics if available
            if worker_stats and worker_name in worker_stats:
                stats = worker_stats[worker_name]
                worker_info.update({
                    'total_tasks': stats.get('total', {}),
                    'pool': stats.get('pool', {}),
                    'rusage': stats.get('rusage', {})
                })

            workers.append(worker_info)

        return workers
