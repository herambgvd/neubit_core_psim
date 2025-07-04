"""
Authentication API views for Core Platform Service.

This module provides REST API endpoints for user authentication,
token management, and user account operations.
"""

import uuid
from datetime import datetime, timedelta
from typing import Dict, Any

from django.contrib.auth import authenticate
from django.contrib.auth import get_user_model
from django.utils import timezone
from django.conf import settings
from rest_framework import status, permissions
from rest_framework.decorators import api_view, permission_classes
from rest_framework.response import Response
from rest_framework.views import APIView
from rest_framework.generics import CreateAPIView, RetrieveUpdateAPIView
from drf_spectacular.utils import extend_schema, OpenApiParameter
from drf_spectacular.types import OpenApiTypes

import structlog

from apps.authentication.serializers import (
    LoginSerializer, TokenRefreshSerializer, UserRegistrationSerializer,
    UserProfileSerializer, ChangePasswordSerializer, ServiceTokenSerializer,
    PermissionCheckSerializer
)
from apps.authentication.services import jwt_service, permission_service, service_auth_service
from apps.users.models import UserSession, ServiceAccount
from apps.shared.pagination import StandardResultsSetPagination

# Configure structured logger
logger = structlog.get_logger(__name__)

User = get_user_model()


class LoginAPIView(APIView):
    """
    User login endpoint.

    Authenticates users and provides JWT tokens for API access.
    """

    permission_classes = [permissions.AllowAny]

    @extend_schema(
        summary="User Login",
        description="Authenticate user and receive JWT tokens",
        request=LoginSerializer,
        responses={
            200: {
                "type": "object",
                "properties": {
                    "success": {"type": "boolean"},
                    "data": {
                        "type": "object",
                        "properties": {
                            "access_token": {"type": "string"},
                            "refresh_token": {"type": "string"},
                            "token_type": {"type": "string"},
                            "expires_in": {"type": "integer"},
                            "user": {"type": "object"}
                        }
                    },
                    "message": {"type": "string"}
                }
            },
            400: {"description": "Invalid credentials"},
            423: {"description": "Account locked"}
        },
        tags=["Authentication"]
    )
    def post(self, request):
        """
        Authenticate user and return JWT tokens.

        Args:
            request: HTTP request with login credentials

        Returns:
            Response with tokens or error message
        """
        serializer = LoginSerializer(data=request.data)

        if not serializer.is_valid():
            return Response({
                'success': False,
                'error': 'Invalid input data',
                'details': serializer.errors
            }, status=status.HTTP_400_BAD_REQUEST)

        username = serializer.validated_data['username']
        password = serializer.validated_data['password']
        remember_me = serializer.validated_data.get('remember_me', False)

        # Get client information
        ip_address = self._get_client_ip(request)
        user_agent = request.META.get('HTTP_USER_AGENT', '')
        device_info = self._extract_device_info(request)

        # Authenticate user
        user = authenticate(
            request=request,
            username=username,
            password=password
        )

        if not user:
            # Try with email if username authentication failed
            try:
                user_by_email = User.objects.get(email=username)
                user = authenticate(
                    request=request,
                    username=user_by_email.username,
                    password=password
                )
            except User.DoesNotExist:
                pass

        if not user:
            logger.warning(
                "login_failed_invalid_credentials",
                username=username,
                ip_address=ip_address,
                correlation_id=getattr(request, 'correlation_id', '')
            )
            return Response({
                'success': False,
                'error': 'Invalid username or password',
                'error_code': 'INVALID_CREDENTIALS'
            }, status=status.HTTP_400_BAD_REQUEST)

        if not user.is_active:
            logger.warning(
                "login_failed_inactive_account",
                user_id=user.id,
                username=user.username,
                ip_address=ip_address
            )
            return Response({
                'success': False,
                'error': 'Account is inactive',
                'error_code': 'ACCOUNT_INACTIVE'
            }, status=status.HTTP_400_BAD_REQUEST)

        if user.is_account_locked:
            logger.warning(
                "login_failed_account_locked",
                user_id=user.id,
                username=user.username,
                ip_address=ip_address
            )
            return Response({
                'success': False,
                'error': 'Account is temporarily locked due to failed login attempts',
                'error_code': 'ACCOUNT_LOCKED'
            }, status=status.HTTP_423_LOCKED)

        # Generate session key
        session_key = str(uuid.uuid4())

        # Generate tokens
        try:
            tokens = jwt_service.generate_user_tokens(
                user=user,
                session_key=session_key,
                device_info=device_info,
                ip_address=ip_address
            )

            # Prepare user data for response
            user_data = {
                'id': user.id,
                'uuid': str(user.uuid),
                'username': user.username,
                'email': user.email,
                'first_name': user.first_name,
                'last_name': user.last_name,
                'is_staff': user.is_staff,
                'is_superuser': user.is_superuser,
                'last_login': user.last_login.isoformat() if user.last_login else None,
                'force_password_change': user.force_password_change,
            }

            logger.info(
                "user_logged_in_successfully",
                user_id=user.id,
                username=user.username,
                ip_address=ip_address,
                session_key=session_key,
                correlation_id=getattr(request, 'correlation_id', '')
            )

            return Response({
                'success': True,
                'data': {
                    **tokens,
                    'user': user_data,
                    'session_key': session_key
                },
                'message': 'Login successful'
            }, status=status.HTTP_200_OK)

        except Exception as e:
            logger.error(
                "token_generation_failed",
                user_id=user.id,
                username=user.username,
                error=str(e),
                correlation_id=getattr(request, 'correlation_id', '')
            )
            return Response({
                'success': False,
                'error': 'Failed to generate authentication tokens',
                'error_code': 'TOKEN_GENERATION_FAILED'
            }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

    def _get_client_ip(self, request) -> str:
        """Extract client IP address from request."""
        x_forwarded_for = request.META.get('HTTP_X_FORWARDED_FOR')
        if x_forwarded_for:
            ip = x_forwarded_for.split(',')[0].strip()
        else:
            ip = request.META.get('REMOTE_ADDR', '0.0.0.0')
        return ip

    def _extract_device_info(self, request) -> Dict[str, Any]:
        """Extract device information from request."""
        user_agent = request.META.get('HTTP_USER_AGENT', '')
        return {
            'user_agent': user_agent,
            'accept_language': request.META.get('HTTP_ACCEPT_LANGUAGE', ''),
            'accept_encoding': request.META.get('HTTP_ACCEPT_ENCODING', ''),
        }


class LogoutAPIView(APIView):
    """
    User logout endpoint.

    Revokes JWT tokens and terminates user session.
    """

    permission_classes = [permissions.IsAuthenticated]

    @extend_schema(
        summary="User Logout",
        description="Logout user and revoke tokens",
        responses={
            200: {"description": "Logout successful"},
            401: {"description": "Authentication required"}
        },
        tags=["Authentication"]
    )
    def post(self, request):
        """
        Logout user and revoke tokens.

        Args:
            request: HTTP request with authentication

        Returns:
            Response indicating logout status
        """
        try:
            # Get token from request
            auth_header = request.META.get('HTTP_AUTHORIZATION', '')
            if auth_header and auth_header.startswith('Bearer '):
                token = auth_header.split(' ')[1]

                # Revoke the token
                jwt_service.revoke_token(token, "user_logout")

            # Terminate user sessions if available
            if hasattr(request, 'token_data') and 'session_key' in request.token_data:
                session_key = request.token_data['session_key']
                try:
                    user_session = UserSession.objects.get(
                        session_key=session_key,
                        user=request.user
                    )
                    user_session.terminate()
                except UserSession.DoesNotExist:
                    pass

            logger.info(
                "user_logged_out",
                user_id=request.user.id,
                username=request.user.username,
                ip_address=self._get_client_ip(request),
                correlation_id=getattr(request, 'correlation_id', '')
            )

            return Response({
                'success': True,
                'message': 'Logout successful'
            }, status=status.HTTP_200_OK)

        except Exception as e:
            logger.error(
                "logout_error",
                user_id=request.user.id if hasattr(request, 'user') else None,
                error=str(e),
                correlation_id=getattr(request, 'correlation_id', '')
            )
            return Response({
                'success': True,  # Still return success for logout
                'message': 'Logout completed with warnings'
            }, status=status.HTTP_200_OK)

    def _get_client_ip(self, request) -> str:
        """Extract client IP address from request."""
        x_forwarded_for = request.META.get('HTTP_X_FORWARDED_FOR')
        if x_forwarded_for:
            ip = x_forwarded_for.split(',')[0].strip()
        else:
            ip = request.META.get('REMOTE_ADDR', '0.0.0.0')
        return ip


class TokenRefreshAPIView(APIView):
    """
    Token refresh endpoint.

    Generates new access token using refresh token.
    """

    permission_classes = [permissions.AllowAny]

    @extend_schema(
        summary="Refresh Access Token",
        description="Generate new access token using refresh token",
        request=TokenRefreshSerializer,
        responses={
            200: {
                "type": "object",
                "properties": {
                    "success": {"type": "boolean"},
                    "data": {
                        "type": "object",
                        "properties": {
                            "access_token": {"type": "string"},
                            "refresh_token": {"type": "string"},
                            "token_type": {"type": "string"},
                            "expires_in": {"type": "integer"}
                        }
                    }
                }
            },
            400: {"description": "Invalid refresh token"}
        },
        tags=["Authentication"]
    )
    def post(self, request):
        """
        Refresh access token.

        Args:
            request: HTTP request with refresh token

        Returns:
            Response with new tokens or error
        """
        serializer = TokenRefreshSerializer(data=request.data)

        if not serializer.is_valid():
            return Response({
                'success': False,
                'error': 'Invalid input data',
                'details': serializer.errors
            }, status=status.HTTP_400_BAD_REQUEST)

        refresh_token = serializer.validated_data['refresh_token']

        # Refresh token
        result = jwt_service.refresh_access_token(refresh_token)

        if not result['valid']:
            logger.warning(
                "token_refresh_failed",
                error=result.get('error'),
                error_code=result.get('error_code'),
                ip_address=self._get_client_ip(request),
                correlation_id=getattr(request, 'correlation_id', '')
            )

            return Response({
                'success': False,
                'error': result.get('error', 'Token refresh failed'),
                'error_code': result.get('error_code', 'REFRESH_FAILED')
            }, status=status.HTTP_400_BAD_REQUEST)

        # Remove validation fields from response
        response_data = {k: v for k, v in result.items() if k != 'valid'}

        logger.info(
            "token_refreshed_successfully",
            ip_address=self._get_client_ip(request),
            correlation_id=getattr(request, 'correlation_id', '')
        )

        return Response({
            'success': True,
            'data': response_data,
            'message': 'Token refreshed successfully'
        }, status=status.HTTP_200_OK)

    def _get_client_ip(self, request) -> str:
        """Extract client IP address from request."""
        x_forwarded_for = request.META.get('HTTP_X_FORWARDED_FOR')
        if x_forwarded_for:
            ip = x_forwarded_for.split(',')[0].strip()
        else:
            ip = request.META.get('REMOTE_ADDR', '0.0.0.0')
        return ip


class UserRegistrationAPIView(CreateAPIView):
    """
    User registration endpoint.

    Creates new user accounts with validation.
    """

    serializer_class = UserRegistrationSerializer
    permission_classes = [permissions.AllowAny]  # Can be restricted based on requirements

    @extend_schema(
        summary="User Registration",
        description="Register new user account",
        tags=["Authentication"]
    )
    def create(self, request, *args, **kwargs):
        """
        Create new user account.

        Args:
            request: HTTP request with user data

        Returns:
            Response with user data or validation errors
        """
        serializer = self.get_serializer(data=request.data)

        if not serializer.is_valid():
            return Response({
                'success': False,
                'error': 'Invalid input data',
                'details': serializer.errors
            }, status=status.HTTP_400_BAD_REQUEST)

        try:
            user = serializer.save()

            logger.info(
                "user_registered",
                user_id=user.id,
                username=user.username,
                email=user.email,
                ip_address=self._get_client_ip(request),
                correlation_id=getattr(request, 'correlation_id', '')
            )

            # Prepare response data
            user_data = {
                'id': user.id,
                'uuid': str(user.uuid),
                'username': user.username,
                'email': user.email,
                'first_name': user.first_name,
                'last_name': user.last_name,
                'created_at': user.created_at.isoformat(),
            }

            return Response({
                'success': True,
                'data': {
                    'user': user_data,
                    'message': 'User registered successfully'
                },
                'message': 'Registration successful'
            }, status=status.HTTP_201_CREATED)

        except Exception as e:
            logger.error(
                "user_registration_failed",
                error=str(e),
                username=request.data.get('username'),
                email=request.data.get('email'),
                correlation_id=getattr(request, 'correlation_id', '')
            )

            return Response({
                'success': False,
                'error': 'Registration failed',
                'error_code': 'REGISTRATION_FAILED'
            }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

    def _get_client_ip(self, request) -> str:
        """Extract client IP address from request."""
        x_forwarded_for = request.META.get('HTTP_X_FORWARDED_FOR')
        if x_forwarded_for:
            ip = x_forwarded_for.split(',')[0].strip()
        else:
            ip = request.META.get('REMOTE_ADDR', '0.0.0.0')
        return ip


class UserProfileAPIView(RetrieveUpdateAPIView):
    """
    User profile management endpoint.

    Allows users to view and update their profile information.
    """

    serializer_class = UserProfileSerializer
    permission_classes = [permissions.IsAuthenticated]

    def get_object(self):
        """Return the current user."""
        return self.request.user

    @extend_schema(
        summary="Get User Profile",
        description="Get current user profile information",
        tags=["User Management"]
    )
    def get(self, request, *args, **kwargs):
        """Get user profile."""
        return super().retrieve(request, *args, **kwargs)

    @extend_schema(
        summary="Update User Profile",
        description="Update current user profile information",
        tags=["User Management"]
    )
    def put(self, request, *args, **kwargs):
        """Update user profile."""
        return super().update(request, *args, **kwargs)

    @extend_schema(
        summary="Partially Update User Profile",
        description="Partially update current user profile information",
        tags=["User Management"]
    )
    def patch(self, request, *args, **kwargs):
        """Partially update user profile."""
        return super().partial_update(request, *args, **kwargs)


class ChangePasswordAPIView(APIView):
    """
    Password change endpoint.

    Allows users to change their password.
    """

    permission_classes = [permissions.IsAuthenticated]

    @extend_schema(
        summary="Change Password",
        description="Change user password",
        request=ChangePasswordSerializer,
        responses={
            200: {"description": "Password changed successfully"},
            400: {"description": "Invalid current password or validation errors"}
        },
        tags=["User Management"]
    )
    def post(self, request):
        """
        Change user password.

        Args:
            request: HTTP request with password data

        Returns:
            Response indicating password change status
        """
        serializer = ChangePasswordSerializer(
            data=request.data,
            context={'user': request.user}
        )

        if not serializer.is_valid():
            return Response({
                'success': False,
                'error': 'Invalid input data',
                'details': serializer.errors
            }, status=status.HTTP_400_BAD_REQUEST)

        try:
            # Change password
            new_password = serializer.validated_data['new_password']
            request.user.set_password(new_password)
            request.user.force_password_change = False
            request.user.save()

            logger.info(
                "password_changed",
                user_id=request.user.id,
                username=request.user.username,
                ip_address=self._get_client_ip(request),
                correlation_id=getattr(request, 'correlation_id', '')
            )

            return Response({
                'success': True,
                'message': 'Password changed successfully'
            }, status=status.HTTP_200_OK)

        except Exception as e:
            logger.error(
                "password_change_failed",
                user_id=request.user.id,
                error=str(e),
                correlation_id=getattr(request, 'correlation_id', '')
            )

            return Response({
                'success': False,
                'error': 'Password change failed',
                'error_code': 'PASSWORD_CHANGE_FAILED'
            }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

    def _get_client_ip(self, request) -> str:
        """Extract client IP address from request."""
        x_forwarded_for = request.META.get('HTTP_X_FORWARDED_FOR')
        if x_forwarded_for:
            ip = x_forwarded_for.split(',')[0].strip()
        else:
            ip = request.META.get('REMOTE_ADDR', '0.0.0.0')
        return ip


class ServiceTokenAPIView(APIView):
    """
    Service token generation endpoint.

    Generates JWT tokens for service-to-service authentication.
    """

    permission_classes = [permissions.IsAuthenticated]

    @extend_schema(
        summary="Generate Service Token",
        description="Generate JWT token for service-to-service authentication",
        request=ServiceTokenSerializer,
        responses={
            200: {
                "type": "object",
                "properties": {
                    "success": {"type": "boolean"},
                    "data": {
                        "type": "object",
                        "properties": {
                            "token": {"type": "string"},
                            "token_type": {"type": "string"},
                            "expires_in": {"type": "integer"},
                            "scopes": {"type": "array", "items": {"type": "string"}}
                        }
                    }
                }
            },
            400: {"description": "Invalid service account"},
            403: {"description": "Insufficient permissions"}
        },
        tags=["Service Authentication"]
    )
    def post(self, request):
        """
        Generate service token.

        Args:
            request: HTTP request with service account details

        Returns:
            Response with service token or error
        """
        # Check if user has permission to generate service tokens
        if not request.user.has_perm('authentication.add_serviceaccount'):
            return Response({
                'success': False,
                'error': 'Insufficient permissions to generate service tokens',
                'error_code': 'INSUFFICIENT_PERMISSIONS'
            }, status=status.HTTP_403_FORBIDDEN)

        serializer = ServiceTokenSerializer(data=request.data)

        if not serializer.is_valid():
            return Response({
                'success': False,
                'error': 'Invalid input data',
                'details': serializer.errors
            }, status=status.HTTP_400_BAD_REQUEST)

        service_account_name = serializer.validated_data['service_account_name']
        requested_scopes = serializer.validated_data.get('scopes', [])

        # Generate token
        ip_address = self._get_client_ip(request)
        result = service_auth_service.generate_service_token(
            service_account_name=service_account_name,
            requested_scopes=requested_scopes,
            ip_address=ip_address
        )

        if not result['success']:
            return Response({
                'success': False,
                'error': result.get('error', 'Service token generation failed'),
                'error_code': result.get('error_code', 'TOKEN_GENERATION_FAILED')
            }, status=status.HTTP_400_BAD_REQUEST)

        logger.info(
            "service_token_generated",
            service_account_name=service_account_name,
            requested_by=request.user.username,
            ip_address=ip_address,
            correlation_id=getattr(request, 'correlation_id', '')
        )

        # Remove success field from response
        response_data = {k: v for k, v in result.items() if k != 'success'}

        return Response({
            'success': True,
            'data': response_data,
            'message': 'Service token generated successfully'
        }, status=status.HTTP_200_OK)

    def _get_client_ip(self, request) -> str:
        """Extract client IP address from request."""
        x_forwarded_for = request.META.get('HTTP_X_FORWARDED_FOR')
        if x_forwarded_for:
            ip = x_forwarded_for.split(',')[0].strip()
        else:
            ip = request.META.get('REMOTE_ADDR', '0.0.0.0')
        return ip


class PermissionCheckAPIView(APIView):
    """
    Permission checking endpoint for microservices.

    Validates user permissions for service operations.
    """

    permission_classes = [permissions.IsAuthenticated]

    @extend_schema(
        summary="Check User Permission",
        description="Check if user has specific permission for service operation",
        request=PermissionCheckSerializer,
        responses={
            200: {
                "type": "object",
                "properties": {
                    "success": {"type": "boolean"},
                    "data": {
                        "type": "object",
                        "properties": {
                            "granted": {"type": "boolean"},
                            "reason": {"type": "string"},
                            "roles": {"type": "array", "items": {"type": "string"}},
                            "permissions": {"type": "array", "items": {"type": "string"}}
                        }
                    }
                }
            }
        },
        tags=["Permission Management"]
    )
    def post(self, request):
        """
        Check user permission.

        Args:
            request: HTTP request with permission check data

        Returns:
            Response with permission check results
        """
        serializer = PermissionCheckSerializer(data=request.data)

        if not serializer.is_valid():
            return Response({
                'success': False,
                'error': 'Invalid input data',
                'details': serializer.errors
            }, status=status.HTTP_400_BAD_REQUEST)

        permission = serializer.validated_data['permission']
        service_name = serializer.validated_data['service_name']
        resource_id = serializer.validated_data.get('resource_id')
        context = serializer.validated_data.get('context', {})

        # Add IP address to context
        context['ip_address'] = self._get_client_ip(request)

        # Check permission
        result = permission_service.check_user_permission(
            user=request.user,
            permission=permission,
            service_name=service_name,
            resource_id=resource_id,
            context=context
        )

        return Response({
            'success': True,
            'data': result,
            'message': 'Permission check completed'
        }, status=status.HTTP_200_OK)

    def _get_client_ip(self, request) -> str:
        """Extract client IP address from request."""
        x_forwarded_for = request.META.get('HTTP_X_FORWARDED_FOR')
        if x_forwarded_for:
            ip = x_forwarded_for.split(',')[0].strip()
        else:
            ip = request.META.get('REMOTE_ADDR', '0.0.0.0')
        return ip


@api_view(['GET'])
@permission_classes([permissions.IsAuthenticated])
@extend_schema(
    summary="Get User Permissions",
    description="Get all permissions for authenticated user",
    parameters=[
        OpenApiParameter(
            name='service_name',
            type=OpenApiTypes.STR,
            location=OpenApiParameter.QUERY,
            description='Filter by service name'
        )
    ],
    responses={
        200: {
            "type": "object",
            "properties": {
                "success": {"type": "boolean"},
                "data": {
                    "type": "object",
                    "properties": {
                        "permissions": {"type": "array", "items": {"type": "string"}},
                        "roles": {"type": "array", "items": {"type": "string"}}
                    }
                }
            }
        }
    },
    tags=["Permission Management"]
)
def get_user_permissions(request):
    """
    Get all permissions for authenticated user.

    Args:
        request: HTTP request

    Returns:
        Response with user permissions
    """
    service_name = request.GET.get('service_name')

    # Get user permissions
    user_permissions = permission_service.get_user_permissions(
        user=request.user,
        service_name=service_name
    )

    # Get user roles
    user_roles = []
    if hasattr(request.user, 'user_roles'):
        roles_qs = request.user.user_roles.filter(is_active=True).select_related('role')
        if service_name:
            roles_qs = roles_qs.filter(
                role__service_scope__in=['', service_name]
            )
        user_roles = [ur.role.name for ur in roles_qs]

    return Response({
        'success': True,
        'data': {
            'permissions': user_permissions,
            'roles': user_roles,
            'service_filter': service_name
        },
        'message': 'User permissions retrieved successfully'
    }, status=status.HTTP_200_OK)