"""
URL configuration for users app.

This module defines URL patterns for user management endpoints.
"""

from django.urls import path, include
from rest_framework.routers import DefaultRouter

from apps.users.views import UserListCreateAPIView, UserDetailAPIView
from apps.users.viewsets import UserViewSet

app_name = 'users'

# Create router for viewsets
router = DefaultRouter()
router.register(r'', UserViewSet, basename='user')

# URL patterns
urlpatterns = [
    # Include router URLs
    path('', include(router.urls)),
]