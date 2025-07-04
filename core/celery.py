"""
Celery configuration for Neubit PSIM Core Platform Service.

This module configures Celery for distributed task processing,
including task routing, serialization, monitoring, and error handling.

Key Features:
- Distributed task processing
- Task routing and prioritization
- Error handling and retries
- Monitoring and logging
- Scheduled tasks support
"""

import os
import sys
from pathlib import Path
from celery import Celery
from django.conf import settings

# Add project directory to Python path
project_dir = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(project_dir))

# Set default Django settings module for Celery
os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'core.settings.development')

# Create Celery application instance
app = Celery('core')

# Configure Celery using Django settings
app.config_from_object('django.conf:settings', namespace='CELERY')

# Auto-discover tasks from all installed Django apps
app.autodiscover_tasks()

# Task routing configuration
app.conf.task_routes = {
    # Authentication tasks
    'apps.authentication.tasks.*': {'queue': 'auth'},

    # User management tasks
    'apps.users.tasks.*': {'queue': 'users'},

    # Location management tasks
    'apps.locations.tasks.*': {'queue': 'locations'},

    # Audit tasks (high priority)
    'apps.audit.tasks.*': {'queue': 'audit', 'priority': 9},

    # Shared service tasks
    'apps.shared.tasks.*': {'queue': 'shared'},

    # Default queue for unspecified tasks
    '*': {'queue': 'default'},
}

# Task execution configuration
app.conf.update(
    # Task result backend
    result_backend=getattr(settings, 'CELERY_RESULT_BACKEND', 'redis://localhost:6379/0'),

    # Task serialization
    task_serializer='json',
    accept_content=['json'],
    result_serializer='json',

    # Timezone configuration
    timezone=getattr(settings, 'TIME_ZONE', 'UTC'),
    enable_utc=True,

    # Task execution settings
    task_always_eager=False,
    task_eager_propagates=True,
    task_ignore_result=False,
    task_store_eager_result=True,

    # Task time limits
    task_time_limit=30 * 60,  # 30 minutes
    task_soft_time_limit=25 * 60,  # 25 minutes

    # Worker configuration
    worker_prefetch_multiplier=1,
    worker_max_tasks_per_child=1000,
    worker_disable_rate_limits=False,

    # Task retry configuration
    task_acks_late=True,
    task_reject_on_worker_lost=True,

    # Monitoring and logging
    worker_send_task_events=True,
    task_send_sent_event=True,

    # Security
    worker_hijack_root_logger=False,
    worker_log_color=False,
)

# Queue configuration
app.conf.task_default_queue = 'default'
app.conf.task_default_exchange = 'default'
app.conf.task_default_exchange_type = 'direct'
app.conf.task_default_routing_key = 'default'

# Queue definitions
app.conf.task_queues = {
    'default': {
        'exchange': 'default',
        'routing_key': 'default',
    },
    'auth': {
        'exchange': 'auth',
        'routing_key': 'auth',
    },
    'users': {
        'exchange': 'users',
        'routing_key': 'users',
    },
    'locations': {
        'exchange': 'locations',
        'routing_key': 'locations',
    },
    'audit': {
        'exchange': 'audit',
        'routing_key': 'audit',
    },
    'shared': {
        'exchange': 'shared',
        'routing_key': 'shared',
    },
}

# Scheduled tasks configuration (Celery Beat)
app.conf.beat_schedule = {
    # Health check task every 5 minutes
    'health-check': {
        'task': 'apps.shared.tasks.perform_health_check',
        'schedule': 300.0,  # 5 minutes
        'options': {'queue': 'shared'}
    },

    # Cleanup expired sessions every hour
    'cleanup-sessions': {
        'task': 'apps.authentication.tasks.cleanup_expired_sessions',
        'schedule': 3600.0,  # 1 hour
        'options': {'queue': 'auth'}
    },

    # Audit log cleanup daily at 2 AM
    'cleanup-audit-logs': {
        'task': 'apps.audit.tasks.cleanup_old_audit_logs',
        'schedule': 86400.0,  # 24 hours
        'options': {'queue': 'audit'}
    },

    # System metrics collection every minute
    'collect-metrics': {
        'task': 'apps.shared.tasks.collect_system_metrics',
        'schedule': 60.0,  # 1 minute
        'options': {'queue': 'shared'}
    },
}

# Error handling configuration
app.conf.task_annotations = {
    '*': {
        'rate_limit': '100/m',  # 100 tasks per minute
        'time_limit': 30 * 60,  # 30 minutes
        'soft_time_limit': 25 * 60,  # 25 minutes
    },
    'apps.audit.tasks.*': {
        'rate_limit': '1000/m',  # Higher rate limit for audit tasks
        'priority': 9,
    },
    'apps.shared.tasks.collect_system_metrics': {
        'rate_limit': '10/m',  # Limit metrics collection
        'time_limit': 60,  # 1 minute for metrics
    },
}


@app.task(bind=True)
def debug_task(self):
    """
    Debug task for testing Celery functionality.

    This task prints request information for debugging purposes.
    """
    print(f'Request: {self.request!r}')


# Signal handlers for monitoring
@app.task(bind=True)
def task_failure_handler(self, task_id, error, traceback):
    """
    Handle task failures with logging and notification.

    Args:
        task_id: ID of the failed task
        error: Error that occurred
        traceback: Error traceback
    """
    from apps.shared.services import NotificationService

    # Log the failure
    print(f'Task {task_id} failed: {error}')

    # Send notification for critical failures
    if hasattr(error, 'critical') and error.critical:
        notification_service = NotificationService()
        notification_service.send_error_notification(
            subject=f'Critical task failure: {task_id}',
            message=f'Task {task_id} failed with error: {error}',
            error_details={'task_id': task_id, 'error': str(error), 'traceback': traceback}
        )


# Worker ready signal
@app.task
def worker_ready_handler(sender=None, **kwargs):
    """
    Handle worker ready signal.

    Args:
        sender: Signal sender
        **kwargs: Additional keyword arguments
    """
    print(f'Worker {sender} is ready')


if __name__ == '__main__':
    app.start()