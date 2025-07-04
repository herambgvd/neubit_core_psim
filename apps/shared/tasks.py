"""
Celery tasks for shared services in Core Platform.

This module contains background tasks that are used across different
apps in the Core Platform, including health checks, metrics collection,
cleanup tasks, and system maintenance.
"""

import time
from datetime import datetime, timedelta
from typing import Dict, Any

import psutil
import structlog
from celery import shared_task
from django.conf import settings
from django.core.cache import cache
from django.utils import timezone

from apps.shared.health.ServiceHealthManager import health_manager
from apps.shared.services.KongIntegrationService import kong_service
from apps.shared.services.NotificationService import notification_service

# Configure structured logger
logger = structlog.get_logger(__name__)


@shared_task(bind=True, max_retries=3, default_retry_delay=60)
def perform_health_check(self):
    """
    Perform comprehensive health check and store results.

    This task runs periodically to check the health of all system
    components and stores the results for monitoring.

    Returns:
        Dict with health check results
    """
    try:
        logger.info("health_check_task_started")

        # Perform health check
        health_data = health_manager.check_all(include_non_critical=True)

        # Store health data in cache for quick access
        cache.set(
            'last_health_check',
            health_data,
            timeout=600  # 10 minutes
        )

        # Check if we need to send alerts
        if health_data['status'] in ['unhealthy', 'degraded']:
            send_health_alert.delay(health_data)

        logger.info(
            "health_check_task_completed",
            status=health_data['status'],
            duration_ms=health_data['duration_ms']
        )

        return health_data

    except Exception as exc:
        logger.error("health_check_task_failed", error=str(exc))
        raise self.retry(exc=exc)


@shared_task(bind=True, max_retries=2, default_retry_delay=30)
def send_health_alert(self, health_data: Dict[str, Any]):
    """
    Send health alert notifications.

    Args:
        health_data: Health check results
    """
    try:
        logger.info("health_alert_task_started", status=health_data['status'])

        # Prepare alert message
        subject = f"PSIM Core Platform Health Alert - {health_data['status'].upper()}"

        unhealthy_components = [
            check['name'] for check in health_data.get('checks', [])
            if check['status'] in ['unhealthy', 'degraded'] and check['critical']
        ]

        message = f"""
        Health Alert for Core Platform Service

        Overall Status: {health_data['status'].upper()}
        Timestamp: {health_data['timestamp']}
        Duration: {health_data['duration_ms']}ms

        Critical Issues:
        {chr(10).join(f"- {component}" for component in unhealthy_components)}

        Please check the health dashboard for detailed information.
        """

        # Send notification
        success = notification_service.send_error_notification(
            subject=subject,
            message=message,
            error_details=health_data
        )

        if success:
            logger.info("health_alert_sent_successfully")
        else:
            logger.error("health_alert_send_failed")

        return success

    except Exception as exc:
        logger.error("health_alert_task_failed", error=str(exc))
        raise self.retry(exc=exc)


@shared_task
def collect_system_metrics():
    """
    Collect system performance metrics.

    This task collects CPU, memory, disk, and network metrics
    and stores them for monitoring and alerting.

    Returns:
        Dict with collected metrics
    """
    try:
        logger.info("metrics_collection_started")

        # Collect system metrics
        metrics = {
            'timestamp': datetime.utcnow().isoformat(),
            'cpu': {
                'percent': psutil.cpu_percent(interval=1),
                'count': psutil.cpu_count(),
                'load_avg': psutil.getloadavg() if hasattr(psutil, 'getloadavg') else None,
            },
            'memory': {
                'percent': psutil.virtual_memory().percent,
                'available_gb': psutil.virtual_memory().available / (1024 ** 3),
                'total_gb': psutil.virtual_memory().total / (1024 ** 3),
                'used_gb': psutil.virtual_memory().used / (1024 ** 3),
            },
            'disk': {
                'percent': psutil.disk_usage('/').percent,
                'free_gb': psutil.disk_usage('/').free / (1024 ** 3),
                'total_gb': psutil.disk_usage('/').total / (1024 ** 3),
                'used_gb': psutil.disk_usage('/').used / (1024 ** 3),
            },
            'network': _get_network_metrics(),
            'processes': {
                'count': len(psutil.pids()),
                'django_processes': _count_django_processes(),
            }
        }

        # Store metrics in cache
        cache_key = f"system_metrics:{int(time.time())}"
        cache.set(cache_key, metrics, timeout=3600)  # 1 hour

        # Keep only last 100 metric entries
        _cleanup_old_metrics()

        logger.info(
            "metrics_collection_completed",
            cpu_percent=metrics['cpu']['percent'],
            memory_percent=metrics['memory']['percent'],
            disk_percent=metrics['disk']['percent']
        )

        return metrics

    except Exception as e:
        logger.error("metrics_collection_failed", error=str(e))
        return None


@shared_task
def cleanup_expired_cache_keys():
    """
    Clean up expired cache keys and perform cache maintenance.

    This task removes stale cache entries and optimizes cache performance.
    """
    try:
        logger.info("cache_cleanup_started")

        # Get cache statistics before cleanup
        try:
            from django_redis import get_redis_connection
            redis_conn = get_redis_connection("default")

            # Get memory usage before cleanup
            memory_before = redis_conn.info()['used_memory']

            # Clean up expired keys (Redis handles this automatically, but we can force it)
            redis_conn.flushexpired() if hasattr(redis_conn, 'flushexpired') else None

            # Clean up old metrics
            _cleanup_old_metrics()

            # Get memory usage after cleanup
            memory_after = redis_conn.info()['used_memory']

            logger.info(
                "cache_cleanup_completed",
                memory_before=memory_before,
                memory_after=memory_after,
                freed_bytes=memory_before - memory_after
            )

        except Exception as e:
            logger.warning("cache_cleanup_partial_failure", error=str(e))

    except Exception as e:
        logger.error("cache_cleanup_failed", error=str(e))


@shared_task(bind=True, max_retries=3, default_retry_delay=60)
def register_with_kong(self):
    """
    Register Core Platform service with Kong Gateway.

    This task ensures the service is properly registered with Kong
    and all routes and plugins are configured correctly.
    """
    try:
        logger.info("kong_registration_task_started")

        # Import here to avoid circular imports
        import asyncio

        # Create event loop for async operation
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)

        try:
            # Register service with Kong
            success = loop.run_until_complete(kong_service.register_service())

            if success:
                logger.info("kong_registration_successful")

                # Store registration status in cache
                cache.set('kong_registration_status', {
                    'registered': True,
                    'timestamp': datetime.utcnow().isoformat(),
                    'success': True
                }, timeout=3600)

                return {'success': True, 'message': 'Service registered with Kong'}
            else:
                raise Exception("Kong registration failed")

        finally:
            loop.close()

    except Exception as exc:
        logger.error("kong_registration_task_failed", error=str(exc))

        # Store failure status
        cache.set('kong_registration_status', {
            'registered': False,
            'timestamp': datetime.utcnow().isoformat(),
            'success': False,
            'error': str(exc)
        }, timeout=300)  # 5 minutes

        raise self.retry(exc=exc)


@shared_task
def cleanup_old_log_files():
    """
    Clean up old log files to prevent disk space issues.

    This task removes log files older than the configured retention period.
    """
    try:
        import os
        import glob
        from pathlib import Path

        logger.info("log_cleanup_started")

        # Get log directory
        log_dir = Path(settings.BASE_DIR).parent / 'logs'
        if not log_dir.exists():
            logger.info("log_cleanup_skipped", reason="Log directory does not exist")
            return

        # Get retention days from settings
        retention_days = getattr(settings, 'LOG_RETENTION_DAYS', 30)
        cutoff_date = timezone.now() - timedelta(days=retention_days)

        # Find old log files
        log_patterns = ['*.log', '*.log.*', '*.out', '*.err']
        deleted_files = 0
        freed_space = 0

        for pattern in log_patterns:
            for log_file in glob.glob(str(log_dir / pattern)):
                file_path = Path(log_file)

                # Check file modification time
                if file_path.exists():
                    file_mtime = datetime.fromtimestamp(file_path.stat().st_mtime, tz=timezone.get_current_timezone())

                    if file_mtime < cutoff_date:
                        file_size = file_path.stat().st_size
                        try:
                            file_path.unlink()
                            deleted_files += 1
                            freed_space += file_size
                            logger.debug("log_file_deleted", file=str(file_path))
                        except OSError as e:
                            logger.warning("log_file_deletion_failed", file=str(file_path), error=str(e))

        logger.info(
            "log_cleanup_completed",
            deleted_files=deleted_files,
            freed_space_mb=freed_space / (1024 ** 2)
        )

        return {
            'deleted_files': deleted_files,
            'freed_space_bytes': freed_space
        }

    except Exception as e:
        logger.error("log_cleanup_failed", error=str(e))
        return None


@shared_task
def generate_daily_health_report():
    """
    Generate daily health report and send to administrators.

    This task creates a comprehensive health report with metrics
    from the past 24 hours and emails it to administrators.
    """
    try:
        logger.info("daily_health_report_started")

        # Get health data from the last 24 hours
        report_data = _collect_daily_health_data()

        # Generate report
        report = _format_health_report(report_data)

        # Send report to administrators
        success = notification_service.send_email(
            to_emails=[email for name, email in getattr(settings, 'ADMINS', [])],
            subject=f"Daily Health Report - {datetime.now().strftime('%Y-%m-%d')}",
            message=report['text'],
            html_message=report['html']
        )

        if success:
            logger.info("daily_health_report_sent")
        else:
            logger.error("daily_health_report_send_failed")

        return success

    except Exception as e:
        logger.error("daily_health_report_failed", error=str(e))
        return False


def _get_network_metrics() -> Dict[str, Any]:
    """Get network interface metrics."""
    try:
        net_io = psutil.net_io_counters()
        return {
            'bytes_sent': net_io.bytes_sent,
            'bytes_recv': net_io.bytes_recv,
            'packets_sent': net_io.packets_sent,
            'packets_recv': net_io.packets_recv,
            'errin': net_io.errin,
            'errout': net_io.errout,
            'dropin': net_io.dropin,
            'dropout': net_io.dropout,
        }
    except Exception:
        return {}


def _count_django_processes() -> int:
    """Count Django-related processes."""
    try:
        django_processes = 0
        for proc in psutil.process_iter(['pid', 'name', 'cmdline']):
            try:
                cmdline = ' '.join(proc.info['cmdline'] or [])
                if 'manage.py' in cmdline or 'gunicorn' in cmdline:
                    django_processes += 1
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                continue
        return django_processes
    except Exception:
        return 0


def _cleanup_old_metrics():
    """Clean up old metric entries from cache."""
    try:
        from django_redis import get_redis_connection
        redis_conn = get_redis_connection("default")

        # Get all metric keys
        metric_keys = redis_conn.keys("*system_metrics:*")

        # Sort by timestamp and keep only last 100
        if len(metric_keys) > 100:
            # Sort keys by timestamp (extracted from key)
            sorted_keys = sorted(metric_keys, key=lambda k: int(k.decode().split(':')[-1]))

            # Delete oldest keys
            keys_to_delete = sorted_keys[:-100]
            if keys_to_delete:
                redis_conn.delete(*keys_to_delete)

        logger.debug("old_metrics_cleaned", deleted_count=len(keys_to_delete) if 'keys_to_delete' in locals() else 0)

    except Exception as e:
        logger.warning("metrics_cleanup_failed", error=str(e))


def _collect_daily_health_data() -> Dict[str, Any]:
    """Collect health data from the last 24 hours."""
    # This is a placeholder - implement based on your metrics storage
    return {
        'avg_response_time': 0,
        'total_requests': 0,
        'error_rate': 0,
        'uptime_percentage': 99.9,
        'critical_issues': [],
        'performance_summary': {}
    }


def _format_health_report(data: Dict[str, Any]) -> Dict[str, str]:
    """Format health data into email report."""
    text_report = f"""
            Daily Health Report - {datetime.now().strftime('%Y-%m-%d')}
            
            Summary:
            - Average Response Time: {data['avg_response_time']}ms
            - Total Requests: {data['total_requests']}
            - Error Rate: {data['error_rate']}%
            - Uptime: {data['uptime_percentage']}%
            
            Critical Issues: {len(data['critical_issues'])}
            
            This is an automated report from the Neubit PSIM Core Platform.
            """

    html_report = f"""
            <h2>Daily Health Report - {datetime.now().strftime('%Y-%m-%d')}</h2>
            <h3>Summary</h3>
            <ul>
                <li>Average Response Time: {data['avg_response_time']}ms</li>
                <li>Total Requests: {data['total_requests']}</li>
                <li>Error Rate: {data['error_rate']}%</li>
                <li>Uptime: {data['uptime_percentage']}%</li>
            </ul>
            <h3>Critical Issues: {len(data['critical_issues'])}</h3>
            <p><em>This is an automated report from the Neubit PSIM Core Platform.</em></p>
            """
    return {'text': text_report, 'html': html_report}
