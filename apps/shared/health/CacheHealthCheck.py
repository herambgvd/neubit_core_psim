import time
import time
from typing import Dict, Any

import psutil
import structlog
from django.conf import settings
from django.core.cache import cache
from apps.shared.health.BaseHealthCheck import BaseHealthCheck, HealthStatus

# Configure structured logger
logger = structlog.get_logger(__name__)


class CacheHealthCheck(BaseHealthCheck):
    """Health check for cache system (Redis)."""

    def __init__(self):
        super().__init__("cache", critical=True)

    def check(self) -> Dict[str, Any]:
        """
        Check cache system health and performance.

        Returns:
            Cache health check results
        """
        try:
            start_time = time.time()

            # Test cache connectivity
            test_key = f"health_check:{int(time.time())}"
            test_value = "health_check_value"

            cache.set(test_key, test_value, timeout=60)
            retrieved_value = cache.get(test_key)
            cache.delete(test_key)

            if retrieved_value != test_value:
                raise Exception("Cache value mismatch")

            operation_time = (time.time() - start_time) * 1000

            # Get cache information
            cache_info = self._get_cache_info()

            # Check cache performance
            performance_status = self._check_cache_performance(operation_time)

            status = HealthStatus.HEALTHY
            message = "Cache is healthy"

            if performance_status['status'] == HealthStatus.DEGRADED:
                status = HealthStatus.DEGRADED
                message = "Cache performance is degraded"

            return self._format_result(
                status=status,
                message=message,
                details={
                    'operation_time_ms': round(operation_time, 2),
                    'performance': performance_status,
                    'cache_info': cache_info
                }
            )

        except Exception as e:
            logger.error("cache_health_check_failed", error=str(e))
            return self._format_result(
                status=HealthStatus.UNHEALTHY,
                message=f"Cache system failed: {str(e)}",
                details={'error': str(e)}
            )

    def _check_cache_performance(self, operation_time: float) -> Dict[str, Any]:
        """
        Check cache performance metrics.

        Args:
            operation_time: Cache operation time in milliseconds

        Returns:
            Performance status information
        """
        # Performance thresholds
        good_threshold = 5.0  # ms
        degraded_threshold = 20.0  # ms

        if operation_time <= good_threshold:
            status = HealthStatus.HEALTHY
            message = "Cache performance is good"
        elif operation_time <= degraded_threshold:
            status = HealthStatus.DEGRADED
            message = "Cache performance is slow"
        else:
            status = HealthStatus.UNHEALTHY
            message = "Cache performance is very slow"

        return {
            'status': status,
            'message': message,
            'operation_time_ms': round(operation_time, 2),
            'thresholds': {
                'good': good_threshold,
                'degraded': degraded_threshold
            }
        }

    def _get_cache_info(self) -> Dict[str, Any]:
        """
        Get cache system information.

        Returns:
            Cache information dictionary
        """
        try:
            # Get Redis info if using django-redis
            from django_redis import get_redis_connection
            redis_conn = get_redis_connection("default")
            redis_info = redis_conn.info()

            return {
                'backend': settings.CACHES['default']['BACKEND'],
                'location': settings.CACHES['default']['LOCATION'],
                'redis_version': redis_info.get('redis_version'),
                'connected_clients': redis_info.get('connected_clients'),
                'used_memory_human': redis_info.get('used_memory_human'),
                'total_commands_processed': redis_info.get('total_commands_processed')
            }
        except Exception:
            return {
                'backend': settings.CACHES['default']['BACKEND'],
                'location': settings.CACHES['default']['LOCATION']
            }
