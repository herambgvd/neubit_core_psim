import time
import time
from typing import Dict, Any

import psutil
import structlog
from django.db import connections, connection
from apps.shared.health.BaseHealthCheck import BaseHealthCheck, HealthStatus

# Configure structured logger
logger = structlog.get_logger(__name__)


class DatabaseHealthCheck(BaseHealthCheck):
    """Health check for database connectivity and performance."""

    def __init__(self):
        super().__init__("database", critical=True)

    def check(self) -> Dict[str, Any]:
        """
        Check database health including connectivity and performance.

        Returns:
            Database health check results
        """
        try:
            start_time = time.time()

            # Test database connectivity
            with connection.cursor() as cursor:
                cursor.execute("SELECT 1")
                cursor.fetchone()

            query_time = (time.time() - start_time) * 1000  # Convert to milliseconds

            # Check database performance
            performance_status = self._check_database_performance(query_time)

            # Get database information
            db_info = self._get_database_info()

            status = HealthStatus.HEALTHY
            message = "Database is healthy"

            if performance_status['status'] == HealthStatus.DEGRADED:
                status = HealthStatus.DEGRADED
                message = "Database performance is degraded"

            return self._format_result(
                status=status,
                message=message,
                details={
                    'query_time_ms': round(query_time, 2),
                    'performance': performance_status,
                    'database_info': db_info
                }
            )

        except Exception as e:
            logger.error("database_health_check_failed", error=str(e))
            return self._format_result(
                status=HealthStatus.UNHEALTHY,
                message=f"Database connection failed: {str(e)}",
                details={'error': str(e)}
            )

    def _check_database_performance(self, query_time: float) -> Dict[str, Any]:
        """
        Check database performance metrics.

        Args:
            query_time: Query execution time in milliseconds

        Returns:
            Performance status information
        """
        # Performance thresholds
        good_threshold = 10.0  # ms
        degraded_threshold = 50.0  # ms

        if query_time <= good_threshold:
            status = HealthStatus.HEALTHY
            message = "Database performance is good"
        elif query_time <= degraded_threshold:
            status = HealthStatus.DEGRADED
            message = "Database performance is slow"
        else:
            status = HealthStatus.UNHEALTHY
            message = "Database performance is very slow"

        return {
            'status': status,
            'message': message,
            'query_time_ms': round(query_time, 2),
            'thresholds': {
                'good': good_threshold,
                'degraded': degraded_threshold
            }
        }

    def _get_database_info(self) -> Dict[str, Any]:
        """
        Get database connection information.

        Returns:
            Database information dictionary
        """
        db_config = connections.databases['default']
        return {
            'engine': db_config['ENGINE'],
            'name': db_config['NAME'],
            'host': db_config['HOST'],
            'port': db_config['PORT'],
            'connection_pool': getattr(db_config, 'POOL_OPTIONS', {})
        }
