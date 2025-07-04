"""
ASGI configuration for Neubit PSIM Core Platform Service.

This module provides the ASGI application object for async/await
support and WebSocket functionality.

The ASGI application supports:
- HTTP requests (sync and async)
- WebSocket connections
- Background tasks
- Real-time features

For production deployment with async features, use servers like
Uvicorn, Hypercorn, or Daphne.
"""

import os
import sys
from pathlib import Path
from django.core.asgi import get_asgi_application

# Add the project directory to the Python path
project_dir = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(project_dir))

# Set default Django settings module
os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'core.settings.production')

# Create ASGI application
application = get_asgi_application()

# Future: Add WebSocket routing and middleware here when needed
# from channels.routing import ProtocolTypeRouter, URLRouter
# from channels.auth import AuthMiddlewareStack
#
# application = ProtocolTypeRouter({
#     "http": get_asgi_application(),
#     "websocket": AuthMiddlewareStack(
#         URLRouter([
#             # WebSocket URL patterns will go here
#         ])
#     ),
# })