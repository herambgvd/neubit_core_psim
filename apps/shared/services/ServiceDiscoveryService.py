from typing import List

import structlog
from django.conf import settings
from apps.shared.services.HTTPClientService import HTTPClientService
from apps.shared.services.CacheService import CacheService
from apps.shared.services.HTTPClientService import ServiceEndpoint


# Configure structured logger
logger = structlog.get_logger(__name__)


class ServiceDiscoveryService:
    """
    Service discovery and registration service.

    This service handles registration with Kong API Gateway
    and discovery of other microservices in the ecosystem.
    """

    def __init__(self):
        """Initialize service discovery."""
        self.http_client = HTTPClientService()
        self.cache_service = CacheService()

        # Kong configuration
        self.kong_admin_url = getattr(settings, 'SERVICE_DISCOVERY', {}).get(
            'KONG_ADMIN_URL', 'http://localhost:8001'
        )

        # Service configuration
        self.service_config = getattr(settings, 'SERVICE_DISCOVERY', {})

    async def register_service(self) -> bool:
        """
        Register this service with Kong API Gateway.

        Returns:
            True if registration successful
        """
        try:
            service_data = {
                'name': self.service_config.get('SERVICE_NAME', 'core'),
                'url': self.service_config.get('SERVICE_URL', 'http://localhost:8000'),
                'retries': 3,
                'connect_timeout': 60000,
                'write_timeout': 60000,
                'read_timeout': 60000,
            }

            # Register service
            response = await self.http_client.request(
                'POST',
                f"{self.kong_admin_url}/services",
                json_data=service_data
            )

            if response.status_code in [200, 201, 409]:  # 409 = already exists
                logger.info("service_registered", service=service_data['name'])
                return True
            else:
                logger.error("service_registration_failed", status=response.status_code)
                return False

        except Exception as e:
            logger.error("service_registration_error", error=str(e))
            return False

    async def discover_services(self) -> List[ServiceEndpoint]:
        """
        Discover available services from Kong.

        Returns:
            List of available service endpoints
        """
        try:
            # Check cache first
            cached_services = self.cache_service.get('discovered_services')
            if cached_services:
                return [ServiceEndpoint(**service) for service in cached_services]

            # Fetch from Kong
            response = await self.http_client.request(
                'GET',
                f"{self.kong_admin_url}/services"
            )

            if response.status_code == 200:
                kong_services = response.json().get('data', [])

                services = []
                for kong_service in kong_services:
                    service = ServiceEndpoint(
                        name=kong_service['name'],
                        url=kong_service['url'],
                        version='1.0.0',  # Default version
                        health_url=f"{kong_service['url']}/health/"
                    )
                    services.append(service)

                # Cache for 5 minutes
                service_dicts = [
                    {
                        'name': s.name,
                        'url': s.url,
                        'version': s.version,
                        'health_url': s.health_url,
                        'timeout': s.timeout,
                        'retries': s.retries
                    }
                    for s in services
                ]
                self.cache_service.set('discovered_services', service_dicts, timeout=300)

                logger.info("services_discovered", count=len(services))
                return services
            else:
                logger.error("service_discovery_failed", status=response.status_code)
                return []

        except Exception as e:
            logger.error("service_discovery_error", error=str(e))
            return []


service_discovery = ServiceDiscoveryService()
