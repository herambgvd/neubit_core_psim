#!/usr/bin/env python
"""
Django's command-line utility for administrative tasks.

Enhanced manage.py for Neubit PSIM Core Platform Service with:
- Proper path configuration for modular structure
- Environment-based settings loading
- Enhanced error handling and logging
- Development utilities
"""

import os
import sys
from pathlib import Path


def main():
    """Run administrative tasks."""

    # Add the current directory to Python path to support the modular structure
    current_dir = Path(__file__).resolve().parent
    if str(current_dir) not in sys.path:
        sys.path.insert(0, str(current_dir))

    # Set default Django settings module based on environment
    environment = os.environ.get('ENVIRONMENT', 'development')
    default_settings = f'core.settings.{environment}'
    os.environ.setdefault('DJANGO_SETTINGS_MODULE', default_settings)

    try:
        from django.core.management import execute_from_command_line
        from django.conf import settings

        # Print helpful information in development
        if 'runserver' in sys.argv and hasattr(settings, 'DEBUG') and settings.DEBUG:
            print("=" * 60)
            print("🚀 Neubit PSIM Core Platform Service")
            print("=" * 60)
            print(f"📍 Environment: {environment}")
            print(f"⚙️  Settings: {os.environ.get('DJANGO_SETTINGS_MODULE', default_settings)}")
            print(
                f"🗄️  Database: {getattr(settings, 'DATABASES', {}).get('default', {}).get('NAME', 'Not configured')}")
            print(f"🔑 Debug Mode: {getattr(settings, 'DEBUG', False)}")
            print("=" * 60)
            print("📡 Available endpoints:")
            print("   • Service Info:  http://localhost:8000/")
            print("   • Health Check:  http://localhost:8000/health/")
            print("   • API Docs:      http://localhost:8000/api/docs/")
            print("   • Admin Panel:   http://localhost:8000/admin/")
            print("=" * 60)

        # Additional helpful commands
        if len(sys.argv) > 1:
            command = sys.argv[1]

            # Show custom help for common commands
            if command in ['help', '--help', '-h'] and len(sys.argv) == 2:
                print("\n🛠️  Custom Management Commands:")
                print("   • wait_for_db           - Wait for database to be ready")
                print("   • create_dev_superuser  - Create development superuser")
                print("\n📊 Health Check Commands:")
                print("   • Check health: curl http://localhost:8000/health/")
                print("   • Check readiness: curl http://localhost:8000/health/ready/")
                print("   • Check liveness: curl http://localhost:8000/health/live/")
                print("\n🔧 Development Commands:")
                print("   • python manage.py shell_plus    - Enhanced shell")
                print("   • python manage.py show_urls     - Show all URLs")
                print("   • python manage.py runserver_plus - Enhanced dev server")
                print()

    except ImportError as exc:
        error_msg = (
            "Couldn't import Django. Are you sure it's installed and "
            "available on your PYTHONPATH environment variable? Did you "
            "forget to activate a virtual environment?\n\n"
            f"Original error: {exc}\n\n"
            "Quick setup:\n"
            "1. Create virtual environment: python -m venv venv\n"
            "2. Activate it: source venv/bin/activate (Linux/Mac) or venv\\Scripts\\activate (Windows)\n"
            "3. Install requirements: pip install -r requirements/dev.txt\n"
        )
        raise ImportError(error_msg) from exc

    except Exception as exc:
        print(f"❌ Error starting Django: {exc}")

        # Provide helpful debugging information
        print("\n🔍 Debugging Information:")
        print(f"   • Python Path: {sys.path[:3]}...")
        print(f"   • Current Directory: {current_dir}")
        print(f"   • Environment: {environment}")
        print(f"   • Settings Module: {os.environ.get('DJANGO_SETTINGS_MODULE', 'Not set')}")

        # Check for common issues
        if 'settings' in str(exc).lower():
            print("\n💡 Possible solutions:")
            print("   • Check your .env file exists and has correct values")
            print("   • Verify DATABASE_URL is properly configured")
            print("   • Ensure SECRET_KEY is set in environment variables")

        raise

    # Execute the Django command
    execute_from_command_line(sys.argv)


if __name__ == '__main__':
    main()