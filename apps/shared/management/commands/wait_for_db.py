"""
Django management command to wait for database availability.

This command is essential for container deployments where the
application container might start before the database container
is fully ready to accept connections.

Usage:
    python manage.py wait_for_db

The command will:
- Test database connectivity repeatedly
- Provide progress feedback
- Exit successfully when database is ready
- Timeout after a reasonable period
"""

import time
import sys
from django.core.management.base import BaseCommand
from django.db import connections, OperationalError
from django.conf import settings


class Command(BaseCommand):
    """Django management command to wait for database availability."""

    help = 'Wait for database to become available'

    def add_arguments(self, parser):
        """
        Add command line arguments.

        Args:
            parser: ArgumentParser instance
        """
        parser.add_argument(
            '--timeout',
            type=int,
            default=60,
            help='Maximum time to wait for database (seconds, default: 60)'
        )

        parser.add_argument(
            '--interval',
            type=int,
            default=2,
            help='Interval between connection attempts (seconds, default: 2)'
        )

        parser.add_argument(
            '--database',
            type=str,
            default='default',
            help='Database alias to check (default: default)'
        )

        parser.add_argument(
            '--quiet',
            action='store_true',
            help='Suppress progress output'
        )

    def handle(self, *args, **options):
        """
        Main command handler.

        Args:
            *args: Positional arguments
            **options: Command options
        """
        timeout = options['timeout']
        interval = options['interval']
        database = options['database']
        quiet = options['quiet']

        if not quiet:
            self.stdout.write(
                self.style.SUCCESS(
                    f'Waiting for database "{database}" to become available...'
                )
            )

        start_time = time.time()

        while True:
            try:
                # Test database connection
                db_conn = connections[database]
                db_conn.ensure_connection()

                # Test with a simple query
                with db_conn.cursor() as cursor:
                    cursor.execute('SELECT 1')
                    cursor.fetchone()

                if not quiet:
                    elapsed = time.time() - start_time
                    self.stdout.write(
                        self.style.SUCCESS(
                            f'Database "{database}" is ready! (took {elapsed:.1f}s)'
                        )
                    )

                # Database is ready
                sys.exit(0)

            except OperationalError as e:
                elapsed = time.time() - start_time

                # Check if timeout exceeded
                if elapsed >= timeout:
                    self.stdout.write(
                        self.style.ERROR(
                            f'Timeout waiting for database "{database}" after {timeout}s'
                        )
                    )
                    self.stdout.write(
                        self.style.ERROR(f'Last error: {str(e)}')
                    )
                    sys.exit(1)

                if not quiet:
                    self.stdout.write(
                        f'Database "{database}" unavailable (retry in {interval}s) - {str(e)}'
                    )

                # Wait before next attempt
                time.sleep(interval)

            except Exception as e:
                self.stdout.write(
                    self.style.ERROR(
                        f'Unexpected error connecting to database "{database}": {str(e)}'
                    )
                )
                sys.exit(1)
