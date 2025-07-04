"""
Django management command to create a development superuser.

This command creates a default superuser account for development
environments, making it easier to access the Django admin interface
during development and testing.

Usage:
    python manage.py create_dev_superuser

The command will:
- Create a superuser if one doesn't already exist
- Use default credentials for development
- Skip creation if superuser already exists
- Only work in DEBUG mode for security
"""

from django.core.management.base import BaseCommand
from django.contrib.auth import get_user_model
from django.conf import settings
from django.db import IntegrityError


class Command(BaseCommand):
    """Django management command to create development superuser."""

    help = 'Create a development superuser account'

    def add_arguments(self, parser):
        """
        Add command line arguments.

        Args:
            parser: ArgumentParser instance
        """
        parser.add_argument(
            '--username',
            type=str,
            default='admin',
            help='Superuser username (default: admin)'
        )

        parser.add_argument(
            '--email',
            type=str,
            default='admin@neubit.in',
            help='Superuser email (default: admin@neubit.in)'
        )

        parser.add_argument(
            '--password',
            type=str,
            default='admin@123',
            help='Superuser password (default: admin@123)'
        )

        parser.add_argument(
            '--force',
            action='store_true',
            help='Force creation even if user exists'
        )

    def handle(self, *args, **options):
        """
        Main command handler.

        Args:
            *args: Positional arguments
            **options: Command options
        """
        # Only allow in development mode for security
        if not settings.DEBUG:
            self.stdout.write(
                self.style.ERROR(
                    'This command can only be run in DEBUG mode for security reasons'
                )
            )
            return

        User = get_user_model()
        username = options['username']
        email = options['email']
        password = options['password']
        force = options['force']

        try:
            # Check if superuser already exists
            if User.objects.filter(username=username).exists():
                if not force:
                    self.stdout.write(
                        self.style.WARNING(
                            f'Superuser "{username}" already exists. Use --force to recreate.'
                        )
                    )
                    return
                else:
                    # Delete existing user if force is specified
                    User.objects.filter(username=username).delete()
                    self.stdout.write(
                        self.style.WARNING(
                            f'Deleted existing superuser "{username}"'
                        )
                    )

            # Create superuser
            user = User.objects.create_superuser(
                username=username,
                email=email,
                password=password
            )

            self.stdout.write(
                self.style.SUCCESS(
                    f'Successfully created superuser "{username}" with email "{email}"'
                )
            )

            if settings.DEBUG:
                self.stdout.write(
                    self.style.WARNING(
                        'Development credentials:'
                    )
                )
                self.stdout.write(f'  Username: {username}')
                self.stdout.write(f'  Password: {password}')
                self.stdout.write(f'  Email: {email}')
                self.stdout.write(
                    self.style.WARNING(
                        'Change these credentials in production!'
                    )
                )

        except IntegrityError as e:
            self.stdout.write(
                self.style.ERROR(
                    f'Failed to create superuser: {str(e)}'
                )
            )
        except Exception as e:
            self.stdout.write(
                self.style.ERROR(
                    f'Unexpected error creating superuser: {str(e)}'
                )
            )