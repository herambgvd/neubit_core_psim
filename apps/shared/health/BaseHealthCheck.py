"""
Comprehensive health check system for Neubit PSIM Core Platform Service.

This module provides health monitoring capabilities for:
- Database connectivity and performance
- Cache system status
- External service dependencies
- System resource monitoring
- Service-specific health checks

The health check system supports multiple output formats and provides
detailed diagnostic information for monitoring and alerting systems.
"""

from datetime import datetime
from typing import Dict, Any, Optional

import psutil
import structlog

# Configure structured logger
logger = structlog.get_logger(__name__)


class HealthStatus:
    """Health status constants."""
    HEALTHY = "healthy"
    DEGRADED = "degraded"
    UNHEALTHY = "unhealthy"
    UNKNOWN = "unknown"


class BaseHealthCheck:
    """
    Base class for health check components.

    All health check components should inherit from this class
    and implement the check() method.
    """

    def __init__(self, name: str, critical: bool = True):
        """
        Initialize health check component.

        Args:
            name: Name of the health check component
            critical: Whether this component is critical for service health
        """
        self.name = name
        self.critical = critical

    def check(self) -> Dict[str, Any]:
        """
        Perform health check.

        Returns:
            Dictionary containing health check results
        """
        raise NotImplementedError("Subclasses must implement check() method")

    def _format_result(self, status: str, message: str, details: Optional[Dict] = None) -> Dict[str, Any]:
        """
        Format health check result.

        Args:
            status: Health status (healthy, degraded, unhealthy)
            message: Human-readable status message
            details: Additional details about the health check

        Returns:
            Formatted health check result
        """
        result = {
            'name': self.name,
            'status': status,
            'message': message,
            'critical': self.critical,
            'timestamp': datetime.utcnow().isoformat(),
        }

        if details:
            result['details'] = details

        return result
