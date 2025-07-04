"""
Django management command to register Core Platform with Kong Gateway.

This command handles the automatic registration of the Core Platform service
with Kong API Gateway, including service registration, route creation,
and plugin configuration.

Usage:
    python manage.py register_with_kong
    python manage.py register_with_kong --force  # Force re-registration
    python manage.py register_with_kong --unregister  # Unregister service
"""

import asyncio

from django.conf import settings
from django.core.management.base import BaseCommand

from apps.shared.services.KongIntegrationService import kong_service


class Command(BaseCommand):
    """Django management command to register with Kong Gateway."""

    help = 'Register Core Platform service with Kong API Gateway'

    def add_arguments(self, parser):
        """
        Add command line arguments.

        Args:
            parser: ArgumentParser instance
        """
        parser.add_argument(
            '--force',
            action='store_true',
            help='Force re-registration even if service already exists'
        )

        parser.add_argument(
            '--unregister',
            action='store_true',
            help='Unregister service from Kong Gateway'
        )

        parser.add_argument(
            '--check-only',
            action='store_true',
            help='Only check registration status without making changes'
        )

        parser.add_argument(
            '--timeout',
            type=int,
            default=30,
            help='Timeout in seconds for Kong operations (default: 30)'
        )

    def handle(self, *args, **options):
        """
        Main command handler.

        Args:
            *args: Positional arguments
            **options: Command options
        """
        # Check if Kong integration is configured
        service_discovery = getattr(settings, 'SERVICE_DISCOVERY', {})
        kong_admin_url = service_discovery.get('KONG_ADMIN_URL')

        if not kong_admin_url:
            self.stdout.write(
                self.style.ERROR(
                    'Kong Admin URL is not configured. '
                    'Please set SERVICE_DISCOVERY.KONG_ADMIN_URL in settings.'
                )
            )
            return

        # Run the appropriate operation
        if options['unregister']:
            self._run_async_operation(self._unregister_service, options)
        elif options['check_only']:
            self._run_async_operation(self._check_registration_status, options)
        else:
            self._run_async_operation(self._register_service, options)

    def _run_async_operation(self, operation, options):
        """
        Run an async operation with proper event loop handling.

        Args:
            operation: Async operation to run
            options: Command options
        """
        try:
            # Create new event loop for the operation
            loop = asyncio.new_event_loop()
            asyncio.set_event_loop(loop)

            # Run the operation
            result = loop.run_until_complete(operation(options))

            # Close the loop
            loop.close()

            return result

        except Exception as e:
            self.stdout.write(
                self.style.ERROR(f'Operation failed: {str(e)}')
            )
            return False

    async def _register_service(self, options):
        """
        Register Core Platform service with Kong.

        Args:
            options: Command options

        Returns:
            True if registration successful
        """
        self.stdout.write(
            self.style.SUCCESS('Starting Kong service registration...')
        )

        # Check current registration status
        health_info = await kong_service.health_check()

        if not health_info['kong_available']:
            self.stdout.write(
                self.style.ERROR(
                    f'Kong Gateway is not available: {health_info.get("error", "Unknown error")}'
                )
            )
            return False

        # Check if service is already registered
        if health_info['service_registered'] and not options['force']:
            self.stdout.write(
                self.style.WARNING(
                    'Service is already registered with Kong. Use --force to re-register.'
                )
            )
            self._display_service_info(health_info['service_info'])
            return True

        # Register the service
        try:
            success = await kong_service.register_service()

            if success:
                self.stdout.write(
                    self.style.SUCCESS(
                        'Successfully registered Core Platform with Kong Gateway!'
                    )
                )

                # Display registration details
                await self._display_registration_details()
                return True
            else:
                self.stdout.write(
                    self.style.ERROR('Failed to register service with Kong Gateway')
                )
                return False

        except Exception as e:
            self.stdout.write(
                self.style.ERROR(f'Registration failed with error: {str(e)}')
            )
            return False

    async def _unregister_service(self, options):
        """
        Unregister Core Platform service from Kong.

        Args:
            options: Command options

        Returns:
            True if unregistration successful
        """
        self.stdout.write(
            self.style.WARNING('Starting Kong service unregistration...')
        )

        try:
            success = await kong_service.unregister_service()

            if success:
                self.stdout.write(
                    self.style.SUCCESS(
                        'Successfully unregistered Core Platform from Kong Gateway!'
                    )
                )
                return True
            else:
                self.stdout.write(
                    self.style.ERROR('Failed to unregister service from Kong Gateway')
                )
                return False

        except Exception as e:
            self.stdout.write(
                self.style.ERROR(f'Unregistration failed with error: {str(e)}')
            )
            return False

    async def _check_registration_status(self, options):
        """
        Check Kong registration status without making changes.

        Args:
            options: Command options

        Returns:
            True if check successful
        """
        self.stdout.write(
            self.style.SUCCESS('Checking Kong registration status...')
        )

        try:
            health_info = await kong_service.health_check()

            # Display Kong availability
            if health_info['kong_available']:
                self.stdout.write(
                    self.style.SUCCESS('✓ Kong Gateway is available')
                )
            else:
                self.stdout.write(
                    self.style.ERROR(
                        f'✗ Kong Gateway is not available: {health_info.get("error", "Unknown error")}'
                    )
                )
                return False

            # Display service registration status
            if health_info['service_registered']:
                self.stdout.write(
                    self.style.SUCCESS('✓ Core Platform is registered with Kong')
                )
                self._display_service_info(health_info['service_info'])
            else:
                self.stdout.write(
                    self.style.WARNING('✗ Core Platform is not registered with Kong')
                )

            return True

        except Exception as e:
            self.stdout.write(
                self.style.ERROR(f'Status check failed with error: {str(e)}')
            )
            return False

    async def _display_registration_details(self):
        """Display detailed registration information."""
        try:
            health_info = await kong_service.health_check()

            if health_info['service_registered']:
                self.stdout.write('\n' + '=' * 50)
                self.stdout.write(self.style.SUCCESS('REGISTRATION DETAILS'))
                self.stdout.write('=' * 50)

                self._display_service_info(health_info['service_info'])

                # Display access URLs
                kong_proxy_url = getattr(settings, 'SERVICE_DISCOVERY', {}).get(
                    'KONG_PROXY_URL', 'http://localhost:8000'
                )

                self.stdout.write('\n' + self.style.SUCCESS('ACCESS URLS:'))
                self.stdout.write(f'  API v1:      {kong_proxy_url}/api/v1/')
                self.stdout.write(f'  Health:      {kong_proxy_url}/health/')
                self.stdout.write(f'  Admin:       {kong_proxy_url}/admin/')
                self.stdout.write(f'  Docs:        {kong_proxy_url}/api/docs/')

        except Exception as e:
            self.stdout.write(
                self.style.WARNING(f'Could not retrieve registration details: {str(e)}')
            )

    def _display_service_info(self, service_info):
        """
        Display service information.

        Args:
            service_info: Service information from Kong
        """
        if not service_info:
            return

        self.stdout.write('\n' + self.style.SUCCESS('SERVICE INFORMATION:'))
        self.stdout.write(f'  Name:        {service_info.get("name", "N/A")}')
        self.stdout.write(f'  URL:         {service_info.get("url", "N/A")}')
        self.stdout.write(f'  Protocol:    {service_info.get("protocol", "N/A")}')
        self.stdout.write(f'  Host:        {service_info.get("host", "N/A")}')
        self.stdout.write(f'  Port:        {service_info.get("port", "N/A")}')
        self.stdout.write(f'  Retries:     {service_info.get("retries", "N/A")}')

        # Display tags if available
        tags = service_info.get('tags', [])
        if tags:
            self.stdout.write(f'  Tags:        {", ".join(tags)}')

        # Display creation/update times
        created_at = service_info.get('created_at')
        updated_at = service_info.get('updated_at')

        if created_at:
            from datetime import datetime
            created_time = datetime.fromtimestamp(created_at)
            self.stdout.write(f'  Created:     {created_time.strftime("%Y-%m-%d %H:%M:%S")}')

        if updated_at and updated_at != created_at:
            updated_time = datetime.fromtimestamp(updated_at)
            self.stdout.write(f'  Updated:     {updated_time.strftime("%Y-%m-%d %H:%M:%S")}')
