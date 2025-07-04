"""
URL configuration for authentication app.

This module defines URL patterns for authentication and user management
endpoints including login, registration, token management, and permissions.
"""

from apps.authentication.viewsets import (
    RoleViewSet, UserRoleViewSet, ServiceAccountViewSet,
    AccessLogViewSet, UserSessionViewSet, PermissionRequestViewSet
)
from django.urls import path, include
from rest_framework.routers import DefaultRouter

from apps.authentication.views import (
    LoginAPIView, LogoutAPIView, TokenRefreshAPIView,
    UserRegistrationAPIView, UserProfileAPIView, ChangePasswordAPIView,
    ServiceTokenAPIView, PermissionCheckAPIView, get_user_permissions
)

app_name = 'authentication'

# Create router for viewsets
router = DefaultRouter()
router.register(r'roles', RoleViewSet, basename='role')
router.register(r'user-roles', UserRoleViewSet, basename='user-role')
router.register(r'service-accounts', ServiceAccountViewSet, basename='service-account')
router.register(r'access-logs', AccessLogViewSet, basename='access-log')
router.register(r'user-sessions', UserSessionViewSet, basename='user-session')
router.register(r'permission-requests', PermissionRequestViewSet, basename='permission-request')

# URL patterns
urlpatterns = [
    # Authentication endpoints
    path('login/', LoginAPIView.as_view(), name='login'),
    path('logout/', LogoutAPIView.as_view(), name='logout'),
    path('refresh/', TokenRefreshAPIView.as_view(), name='token-refresh'),
    path('register/', UserRegistrationAPIView.as_view(), name='register'),

    # User management endpoints
    path('profile/', UserProfileAPIView.as_view(), name='user-profile'),
    path('change-password/', ChangePasswordAPIView.as_view(), name='change-password'),

    # Service authentication endpoints
    path('service-token/', ServiceTokenAPIView.as_view(), name='service-token'),

    # Permission management endpoints
    path('check-permission/', PermissionCheckAPIView.as_view(), name='check-permission'),
    path('user-permissions/', get_user_permissions, name='user-permissions'),

    # Include router URLs
    path('', include(router.urls)),
]
