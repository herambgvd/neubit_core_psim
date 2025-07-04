"""
Kong API Gateway integration service for Core Platform.

This service handles automatic registration of the Core Platform service
with Kong Gateway, including service registration, route creation,
and plugin configuration.
"""

import json
import time
from typing import Dict, List, Any, Optional
from urllib.parse import urljoin

import structlog
from django.conf import settings

from apps.shared.services.HTTPClientService import HTTPClientService

# Configure structured logger
logger = structlog.get_logger(__name__)


class KongIntegrationService:
    """
    Service for integrating Core Platform with Kong API Gateway.

    This service provides:
    - Automatic service registration with Kong
    - Route configuration and management
    - Plugin setup for authentication and security
    - Health check integration
    """

    def __init__(self):
        """Initialize Kong integration service."""
        self.http_client = HTTPClientService()
        self.kong_admin_url = getattr(settings, 'SERVICE_DISCOVERY', {}).get(
            'KONG_ADMIN_URL', 'http://localhost:8001'
        )
        self.service_config = getattr(settings, 'SERVICE_DISCOVERY', {})
        self.service_name = self.service_config.get('SERVICE_NAME', 'core-platform')
        self.service_url = self.service_config.get('SERVICE_URL', 'http://localhost:8000')

    async def register_service(self) -> bool:
        """
        Register Core Platform service with Kong Gateway.

        Returns:
            True if registration successful, False otherwise
        """
        try:
            # Check if service already exists
            existing_service = await self._get_service(self.service_name)

            if existing_service:
                logger.info("service_already_registered", service_name=self.service_name)
                return await self._update_service()
            else:
                return await self._create_service()

        except Exception as e:
            logger.error("service_registration_failed", error=str(e))
            return False

    async def _create_service(self) -> bool:
        """Create new service in Kong."""
        service_data = {
            'name': self.service_name,
            'url': self.service_url,
            'protocol': 'http',
            'host': self._extract_host_from_url(self.service_url),
            'port': self._extract_port_from_url(self.service_url),
            'path': '/',
            'retries': 3,
            'connect_timeout': 60000,
            'write_timeout': 60000,
            'read_timeout': 60000,
            'tags': ['core-platform', 'microservice', 'psim']
        }

        try:
            response = await self.http_client.request(
                'POST',
                f"{self.kong_admin_url}/services",
                json_data=service_data
            )

            if response.status_code in [200, 201]:
                logger.info("service_created_successfully", service_name=self.service_name)
                await self._create_routes()
                await self._configure_plugins()
                return True
            else:
                logger.error("service_creation_failed",
                             status_code=response.status_code,
                             response=response.text)
                return False

        except Exception as e:
            logger.error("service_creation_error", error=str(e))
            return False

    async def _update_service(self) -> bool:
        """Update existing service in Kong."""
        service_data = {
            'url': self.service_url,
            'retries': 3,
            'connect_timeout': 60000,
            'write_timeout': 60000,
            'read_timeout': 60000,
        }

        try:
            response = await self.http_client.request(
                'PATCH',
                f"{self.kong_admin_url}/services/{self.service_name}",
                json_data=service_data
            )

            if response.status_code == 200:
                logger.info("service_updated_successfully", service_name=self.service_name)
                return True
            else:
                logger.error("service_update_failed",
                             status_code=response.status_code,
                             response=response.text)
                return False

        except Exception as e:
            logger.error("service_update_error", error=str(e))
            return False

    async def _create_routes(self) -> bool:
        """Create routes for the Core Platform service."""
        routes = [
            {
                'name': f'{self.service_name}-api-v1',
                'service': {'name': self.service_name},
                'paths': ['/api/v1'],
                'strip_path': False,
                'preserve_host': True,
                'protocols': ['http', 'https'],
                'tags': ['api', 'v1']
            },
            {
                'name': f'{self.service_name}-health',
                'service': {'name': self.service_name},
                'paths': ['/health'],
                'strip_path': False,
                'preserve_host': True,
                'protocols': ['http', 'https'],
                'tags': ['health', 'monitoring']
            },
            {
                'name': f'{self.service_name}-admin',
                'service': {'name': self.service_name},
                'paths': ['/admin'],
                'strip_path': False,
                'preserve_host': True,
                'protocols': ['http', 'https'],
                'tags': ['admin']
            }
        ]

        success_count = 0
        for route_data in routes:
            try:
                # Check if route already exists
                existing_route = await self._get_route(route_data['name'])

                if existing_route:
                    # Update existing route
                    response = await self.http_client.request(
                        'PATCH',
                        f"{self.kong_admin_url}/routes/{route_data['name']}",
                        json_data=route_data
                    )
                else:
                    # Create new route
                    response = await self.http_client.request(
                        'POST',
                        f"{self.kong_admin_url}/routes",
                        json_data=route_data
                    )

                if response.status_code in [200, 201]:
                    success_count += 1
                    logger.info("route_configured", route_name=route_data['name'])
                else:
                    logger.error("route_configuration_failed",
                                 route_name=route_data['name'],
                                 status_code=response.status_code)

            except Exception as e:
                logger.error("route_configuration_error",
                             route_name=route_data['name'],
                             error=str(e))

        return success_count == len(routes)

    async def _configure_plugins(self) -> bool:
        """Configure Kong plugins for the service."""
        plugins = [
            {
                'name': 'cors',
                'service': {'name': self.service_name},
                'config': {
                    'origins': ['*'],
                    'methods': ['GET', 'POST', 'PUT', 'PATCH', 'DELETE', 'OPTIONS'],
                    'headers': ['Accept', 'Accept-Version', 'Content-Length', 'Content-MD5',
                                'Content-Type', 'Date', 'X-Auth-Token', 'Authorization'],
                    'exposed_headers': ['X-Auth-Token'],
                    'credentials': True,
                    'max_age': 3600,
                    'preflight_continue': False
                }
            },
            {
                'name': 'rate-limiting',
                'service': {'name': self.service_name},
                'config': {
                    'minute': 100,
                    'hour': 1000,
                    'policy': 'local',
                    'fault_tolerant': True,
                    'hide_client_headers': False
                }
            },
            {
                'name': 'request-id',
                'service': {'name': self.service_name},
                'config': {
                    'header_name': 'X-Request-ID',
                    'echo_downstream': True
                }
            },
            {
                'name': 'prometheus',
                'service': {'name': self.service_name},
                'config': {
                    'per_consumer': True,
                    'status_code_metrics': True,
                    'latency_metrics': True,
                    'bandwidth_metrics': True,
                    'upstream_health_metrics': True
                }
            }
        ]

        success_count = 0
        for plugin_data in plugins:
            try:
                # Check if plugin already exists
                existing_plugins = await self._get_service_plugins(self.service_name)
                plugin_exists = any(
                    plugin['name'] == plugin_data['name']
                    for plugin in existing_plugins
                )

                if plugin_exists:
                    logger.info("plugin_already_exists",
                                plugin_name=plugin_data['name'],
                                service=self.service_name)
                    success_count += 1
                    continue

                response = await self.http_client.request(
                    'POST',
                    f"{self.kong_admin_url}/plugins",
                    json_data=plugin_data
                )

                if response.status_code in [200, 201]:
                    success_count += 1
                    logger.info("plugin_configured",
                                plugin_name=plugin_data['name'],
                                service=self.service_name)
                else:
                    logger.error("plugin_configuration_failed",
                                 plugin_name=plugin_data['name'],
                                 status_code=response.status_code)

            except Exception as e:
                logger.error("plugin_configuration_error",
                             plugin_name=plugin_data['name'],
                             error=str(e))

        return success_count == len(plugins)

    async def _get_service(self, service_name: str) -> Optional[Dict]:
        """Get service information from Kong."""
        try:
            response = await self.http_client.request(
                'GET',
                f"{self.kong_admin_url}/services/{service_name}"
            )

            if response.status_code == 200:
                return response.json()
            elif response.status_code == 404:
                return None
            else:
                logger.warning("get_service_unexpected_response",
                               service_name=service_name,
                               status_code=response.status_code)
                return None

        except Exception as e:
            logger.error("get_service_error",
                         service_name=service_name,
                         error=str(e))
            return None

    async def _get_route(self, route_name: str) -> Optional[Dict]:
        """Get route information from Kong."""
        try:
            response = await self.http_client.request(
                'GET',
                f"{self.kong_admin_url}/routes/{route_name}"
            )

            if response.status_code == 200:
                return response.json()
            elif response.status_code == 404:
                return None
            else:
                return None

        except Exception:
            return None

    async def _get_service_plugins(self, service_name: str) -> List[Dict]:
        """Get all plugins for a service."""
        try:
            response = await self.http_client.request(
                'GET',
                f"{self.kong_admin_url}/services/{service_name}/plugins"
            )

            if response.status_code == 200:
                return response.json().get('data', [])
            else:
                return []

        except Exception:
            return []

    def _extract_host_from_url(self, url: str) -> str:
        """Extract host from URL."""
        from urllib.parse import urlparse
        parsed = urlparse(url)
        return parsed.hostname or 'localhost'

    def _extract_port_from_url(self, url: str) -> int:
        """Extract port from URL."""
        from urllib.parse import urlparse
        parsed = urlparse(url)
        if parsed.port:
            return parsed.port
        return 80 if parsed.scheme == 'http' else 443

    async def health_check(self) -> Dict[str, Any]:
        """
        Check Kong connectivity and service registration status.

        Returns:
            Dictionary with Kong health information
        """
        try:
            # Check Kong admin API
            response = await self.http_client.request(
                'GET',
                f"{self.kong_admin_url}/status"
            )

            if response.status_code != 200:
                return {
                    'kong_available': False,
                    'service_registered': False,
                    'error': f'Kong admin API returned {response.status_code}'
                }

            # Check if service is registered
            service_info = await self._get_service(self.service_name)

            return {
                'kong_available': True,
                'service_registered': service_info is not None,
                'service_info': service_info,
                'kong_status': response.json()
            }

        except Exception as e:
            return {
                'kong_available': False,
                'service_registered': False,
                'error': str(e)
            }

    async def unregister_service(self) -> bool:
        """
        Unregister service from Kong (useful for testing/cleanup).

        Returns:
            True if unregistration successful
        """
        try:
            response = await self.http_client.request(
                'DELETE',
                f"{self.kong_admin_url}/services/{self.service_name}"
            )

            if response.status_code in [204, 404]:
                logger.info("service_unregistered", service_name=self.service_name)
                return True
            else:
                logger.error("service_unregistration_failed",
                             status_code=response.status_code)
                return False

        except Exception as e:
            logger.error("service_unregistration_error", error=str(e))
            return False


# Global Kong integration service instance
kong_service = KongIntegrationService()