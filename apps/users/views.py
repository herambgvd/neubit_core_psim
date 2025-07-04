"""
User management API views for Core Platform Service.

This module provides REST API endpoints for user management operations
including user CRUD operations, profile management, and user-specific actions.
"""

import structlog
from django.contrib.auth import get_user_model
from django.db.models import Q, Count
from django.utils import timezone
from rest_framework import status, permissions
from rest_framework.decorators import api_view, permission_classes
from rest_framework.response import Response
from rest_framework.views import APIView
from rest_framework.generics import ListCreateAPIView, RetrieveUpdateDestroyAPIView
from drf_spectacular.utils import extend_schema, OpenApiParameter
from drf_spectacular.types import OpenApiTypes

from apps.users.serializers import (
    UserSerializer, UserCreateSerializer, UserListSerializer,
    UserProfileUpdateSerializer, UserActivitySerializer, BulkUserActionSerializer
)
from apps.authentication.serializers import UserRoleSerializer
from apps.authentication.models import UserRole
from apps.shared.pagination import StandardResultsSetPagination

# Configure structured logger
logger = structlog.get_logger(__name__)

User = get_user_model()


class UserListCreateAPIView(ListCreateAPIView):
    """
    API view for listing and creating users.

    GET: List all users with filtering and search capabilities
    POST: Create new user account
    """

    queryset = User.objects.all()
    permission_classes = [permissions.IsAuthenticated]
    pagination_class = StandardResultsSetPagination

    def get_serializer_class(self):
        """Return appropriate serializer based on action."""
        if self.request.method == 'POST':
            return UserCreateSerializer
        return UserListSerializer

    def get_queryset(self):
        """Filter queryset based on user permissions and query parameters."""
        queryset = User.objects.select_related('profile', 'manager').annotate(
            active_roles_count=Count('user_roles', filter=Q(user_roles__is_active=True))
        )

        # Exclude service accounts unless specifically requested
        if not self.request.query_params.get('include_service_accounts'):
            queryset = queryset.filter(is_service_account=False)

        # Apply search filters
        search = self.request.query_params.get('search')
        if search:
            queryset = queryset.filter(
                Q(username__icontains=search) |
                Q(email__icontains=search) |
                Q(first_name__icontains=search) |
                Q(last_name__icontains=search) |
                Q(employee_id__icontains=search) |
                Q(department__icontains=search)
            )

        # Apply filters
        is_active = self.request.query_params.get('is_active')
        if is_active is not None:
            queryset = queryset.filter(is_active=is_active.lower() == 'true')

        is_staff = self.request.query_params.get('is_staff')
        if is_staff is not None:
            queryset = queryset.filter(is_staff=is_staff.lower() == 'true')

        department = self.request.query_params.get('department')
        if department:
            queryset = queryset.filter(department__icontains=department)

        # Filter based on user permissions
        if not self.request.user.is_superuser:
            if self.request.user.has_perm('users.view_user'):
                # User has permission to view all users
                pass
            else:
                # User can only see themselves and their subordinates
                user_filter = Q(id=self.request.user.id)

                # Add subordinates if user is a manager
                if hasattr(self.request.user, 'subordinates'):
                    subordinate_ids = self.request.user.subordinates.values_list('id', flat=True)
                    user_filter |= Q(id__in=subordinate_ids)

                queryset = queryset.filter(user_filter)

        # Apply ordering
        ordering = self.request.query_params.get('ordering', 'username')
        if ordering.lstrip('-') in ['username', 'email', 'first_name', 'last_name', 'created_at', 'last_login']:
            queryset = queryset.order_by(ordering)

        return queryset

    @extend_schema(
        summary="List Users",
        description="Get list of users with filtering and search capabilities",
        parameters=[
            OpenApiParameter(name='search', type=OpenApiTypes.STR,
                             description='Search in username, email, name, employee_id, department'),
            OpenApiParameter(name='is_active', type=OpenApiTypes.BOOL, description='Filter by active status'),
            OpenApiParameter(name='is_staff', type=OpenApiTypes.BOOL, description='Filter by staff status'),
            OpenApiParameter(name='department', type=OpenApiTypes.STR, description='Filter by department'),
            OpenApiParameter(name='include_service_accounts', type=OpenApiTypes.BOOL,
                             description='Include service accounts'),
            OpenApiParameter(name='ordering', type=OpenApiTypes.STR,
                             description='Order by field (username, email, first_name, last_name, created_at, last_login)'),
        ],
        tags=["User Management"]
    )
    def get(self, request, *args, **kwargs):
        """List users with filtering."""
        return super().list(request, *args, **kwargs)

    @extend_schema(
        summary="Create User",
        description="Create new user account",
        tags=["User Management"]
    )
    def post(self, request, *args, **kwargs):
        """Create new user."""
        # Check permissions
        if not request.user.has_perm('users.add_user'):
            return Response(
                {'error': 'Insufficient permissions to create users'},
                status=status.HTTP_403_FORBIDDEN
            )

        return super().create(request, *args, **kwargs)

    def perform_create(self, serializer):
        """Create user with audit logging."""
        user = serializer.save(created_by=self.request.user)

        logger.info(
            "user_created_via_api",
            user_id=user.id,
            username=user.username,
            email=user.email,
            created_by=self.request.user.username,
            correlation_id=getattr(self.request, 'correlation_id', '')
        )


class UserDetailAPIView(RetrieveUpdateDestroyAPIView):
    """
    API view for user detail operations.

    GET: Retrieve user details
    PUT/PATCH: Update user information
    DELETE: Soft delete user (deactivate)
    """

    queryset = User.objects.all()
    serializer_class = UserSerializer
    permission_classes = [permissions.IsAuthenticated]

    def get_queryset(self):
        """Filter queryset based on user permissions."""
        queryset = User.objects.select_related('profile', 'manager')

        # Filter based on user permissions
        if not self.request.user.is_superuser:
            if self.request.user.has_perm('users.view_user'):
                # User has permission to view all users
                pass
            else:
                # User can only access themselves and their subordinates
                user_filter = Q(id=self.request.user.id)

                # Add subordinates if user is a manager
                if hasattr(self.request.user, 'subordinates'):
                    subordinate_ids = self.request.user.subordinates.values_list('id', flat=True)
                    user_filter |= Q(id__in=subordinate_ids)

                queryset = queryset.filter(user_filter)

        return queryset

    @extend_schema(
        summary="Get User Details",
        description="Retrieve detailed user information",
        tags=["User Management"]
    )
    def get(self, request, *args, **kwargs):
        """Get user details."""
        return super().retrieve(request, *args, **kwargs)

    @extend_schema(
        summary="Update User",
        description="Update user information",
        tags=["User Management"]
    )
    def put(self, request, *args, **kwargs):
        """Update user (full update)."""
        return self._handle_update(request, *args, **kwargs)

    @extend_schema(
        summary="Partially Update User",
        description="Partially update user information",
        tags=["User Management"]
    )
    def patch(self, request, *args, **kwargs):
        """Update user (partial update)."""
        return self._handle_update(request, *args, **kwargs)

    def _handle_update(self, request, *args, **kwargs):
        """Handle user update with permission checking."""
        user = self.get_object()

        # Check permissions
        if not (request.user == user or
                request.user.has_perm('users.change_user') or
                (hasattr(request.user, 'subordinates') and user in request.user.subordinates.all())):
            return Response(
                {'error': 'Insufficient permissions to update this user'},
                status=status.HTTP_403_FORBIDDEN
            )

        # Use profile update serializer for comprehensive updates
        if request.method == 'PATCH':
            serializer = UserProfileUpdateSerializer(
                user, data=request.data, partial=True, context={'request': request}
            )
        else:
            serializer = UserProfileUpdateSerializer(
                user, data=request.data, context={'request': request}
            )

        if serializer.is_valid():
            serializer.save()
            return Response(UserSerializer(user, context={'request': request}).data)

        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

    @extend_schema(
        summary="Delete User",
        description="Soft delete user (deactivate account)",
        tags=["User Management"]
    )
    def delete(self, request, *args, **kwargs):
        """Soft delete user."""
        user = self.get_object()

        # Check permissions
        if not request.user.has_perm('users.delete_user'):
            return Response(
                {'error': 'Insufficient permissions to delete users'},
                status=status.HTTP_403_FORBIDDEN
            )

        # Prevent self-deletion
        if user == request.user:
            return Response(
                {'error': 'Cannot delete your own account'},
                status=status.HTTP_400_BAD_REQUEST
            )

        # Soft delete (deactivate)
        user.is_active = False
        user.save()

        logger.info(
            "user_deactivated_via_api",
            user_id=user.id,
            username=user.username,
            deactivated_by=request.user.username,
            correlation_id=getattr(request, 'correlation_id', '')
        )

        return Response(
            {'message': 'User deactivated successfully'},
            status=status.HTTP_204_NO_CONTENT
        )


@api_view(['GET'])
@permission_classes([permissions.IsAuthenticated])
@extend_schema(
    summary="Get User Roles",
    description="Get all roles assigned to a specific user",
    parameters=[
        OpenApiParameter(name='user_id', type=OpenApiTypes.INT, location=OpenApiParameter.PATH)
    ],
    tags=["User Management"]
)
def get_user_roles(request, user_id):
    """Get user's role assignments."""
    try:
        user = User.objects.get(id=user_id)

        # Check permissions
        if not (request.user == user or
                request.user.has_perm('authentication.view_userrole') or
                (hasattr(request.user, 'subordinates') and user in request.user.subordinates.all())):
            return Response(
                {'error': 'Insufficient permissions to view user roles'},
                status=status.HTTP_403_FORBIDDEN
            )

        user_roles = UserRole.objects.filter(
            user=user,
            is_active=True
        ).select_related('role', 'assigned_by')

        serializer = UserRoleSerializer(user_roles, many=True)

        return Response({
            'success': True,
            'data': {
                'user': {
                    'id': user.id,
                    'username': user.username,
                    'email': user.email,
                    'full_name': user.get_full_name()
                },
                'roles': serializer.data,
                'total_count': user_roles.count()
            },
            'message': 'User roles retrieved successfully'
        })

    except User.DoesNotExist:
        return Response(
            {'error': 'User not found'},
            status=status.HTTP_404_NOT_FOUND
        )


@api_view(['POST'])
@permission_classes([permissions.IsAuthenticated])
@extend_schema(
    summary="Assign Role to User",
    description="Assign a role to the specified user",
    request={
        "type": "object",
        "properties": {
            "role_id": {"type": "integer", "description": "ID of the role to assign"},
            "scope_type": {"type": "string", "enum": ["global", "location", "department", "project"],
                           "default": "global"},
            "scope_id": {"type": "string", "description": "Scope identifier"},
            "expires_at": {"type": "string", "format": "date-time", "description": "Role expiration time"}
        },
        "required": ["role_id"]
    },
    tags=["User Management"]
)
def assign_user_role(request, user_id):
    """Assign role to user."""
    try:
        user = User.objects.get(id=user_id)

        # Check permissions
        if not request.user.has_perm('authentication.add_userrole'):
            return Response(
                {'error': 'Insufficient permissions to assign roles'},
                status=status.HTTP_403_FORBIDDEN
            )

        role_id = request.data.get('role_id')
        scope_type = request.data.get('scope_type', 'global')
        scope_id = request.data.get('scope_id', '')
        expires_at = request.data.get('expires_at')

        if not role_id:
            return Response(
                {'error': 'role_id is required'},
                status=status.HTTP_400_BAD_REQUEST
            )

        try:
            from apps.authentication.models import Role
            role = Role.objects.get(id=role_id, is_active=True)
        except Role.DoesNotExist:
            return Response(
                {'error': 'Role not found or inactive'},
                status=status.HTTP_404_NOT_FOUND
            )

        # Check if assignment already exists
        if UserRole.objects.filter(
                user=user,
                role=role,
                scope_type=scope_type,
                scope_id=scope_id,
                is_active=True
        ).exists():
            return Response(
                {'error': 'User already has this role assignment'},
                status=status.HTTP_400_BAD_REQUEST
            )

        # Create role assignment
        from apps.authentication.services import permission_service

        try:
            from datetime import datetime
            expires_datetime = None
            if expires_at:
                expires_datetime = datetime.fromisoformat(expires_at.replace('Z', '+00:00'))

            user_role = permission_service.assign_role_to_user(
                user=user,
                role=role,
                assigned_by=request.user,
                scope_type=scope_type,
                scope_id=scope_id,
                expires_at=expires_datetime
            )

            serializer = UserRoleSerializer(user_role)

            return Response({
                'success': True,
                'data': {
                    'message': 'Role assigned successfully',
                    'user_role': serializer.data
                }
            }, status=status.HTTP_201_CREATED)

        except Exception as e:
            logger.error(
                "role_assignment_failed",
                user_id=user.id,
                role_id=role.id,
                error=str(e),
                correlation_id=getattr(request, 'correlation_id', '')
            )

            return Response(
                {'error': 'Failed to assign role'},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )

    except User.DoesNotExist:
        return Response(
            {'error': 'User not found'},
            status=status.HTTP_404_NOT_FOUND
        )


@api_view(['POST'])
@permission_classes([permissions.IsAuthenticated])
@extend_schema(
    summary="Revoke Role from User",
    description="Revoke a role assignment from the specified user",
    request={
        "type": "object",
        "properties": {
            "role_id": {"type": "integer", "description": "ID of the role to revoke"},
            "scope_type": {"type": "string", "enum": ["global", "location", "department", "project"],
                           "default": "global"},
            "scope_id": {"type": "string", "description": "Scope identifier"}
        },
        "required": ["role_id"]
    },
    tags=["User Management"]
)
def revoke_user_role(request, user_id):
    """Revoke role from user."""
    try:
        user = User.objects.get(id=user_id)

        # Check permissions
        if not request.user.has_perm('authentication.change_userrole'):
            return Response(
                {'error': 'Insufficient permissions to revoke roles'},
                status=status.HTTP_403_FORBIDDEN
            )

        role_id = request.data.get('role_id')
        scope_type = request.data.get('scope_type', 'global')
        scope_id = request.data.get('scope_id', '')

        if not role_id:
            return Response(
                {'error': 'role_id is required'},
                status=status.HTTP_400_BAD_REQUEST
            )

        try:
            from apps.authentication.models import Role
            role = Role.objects.get(id=role_id)
        except Role.DoesNotExist:
            return Response(
                {'error': 'Role not found'},
                status=status.HTTP_404_NOT_FOUND
            )

        # Revoke role assignment
        from apps.authentication.services import permission_service

        success = permission_service.revoke_role_from_user(
            user=user,
            role=role,
            revoked_by=request.user,
            scope_type=scope_type,
            scope_id=scope_id
        )

        if success:
            return Response({
                'success': True,
                'message': 'Role revoked successfully'
            })
        else:
            return Response(
                {'error': 'Role assignment not found or already inactive'},
                status=status.HTTP_404_NOT_FOUND
            )

    except User.DoesNotExist:
        return Response(
            {'error': 'User not found'},
            status=status.HTTP_404_NOT_FOUND
        )


@api_view(['GET'])
@permission_classes([permissions.IsAuthenticated])
@extend_schema(
    summary="Get User Permissions",
    description="Get all permissions for a specific user",
    parameters=[
        OpenApiParameter(name='user_id', type=OpenApiTypes.INT, location=OpenApiParameter.PATH),
        OpenApiParameter(name='service_name', type=OpenApiTypes.STR, description='Filter by service name')
    ],
    tags=["User Management"]
)
def get_user_permissions(request, user_id):
    """Get user's permissions."""
    try:
        user = User.objects.get(id=user_id)

        # Check permissions
        if not (request.user == user or
                request.user.has_perm('authentication.view_userrole') or
                (hasattr(request.user, 'subordinates') and user in request.user.subordinates.all())):
            return Response(
                {'error': 'Insufficient permissions to view user permissions'},
                status=status.HTTP_403_FORBIDDEN
            )

        service_name = request.query_params.get('service_name')

        from apps.authentication.services import permission_service

        permissions = permission_service.get_user_permissions(
            user=user,
            service_name=service_name
        )

        return Response({
            'success': True,
            'data': {
                'user': {
                    'id': user.id,
                    'username': user.username,
                    'email': user.email,
                    'full_name': user.get_full_name()
                },
                'permissions': permissions,
                'service_filter': service_name,
                'total_count': len(permissions)
            },
            'message': 'User permissions retrieved successfully'
        })

    except User.DoesNotExist:
        return Response(
            {'error': 'User not found'},
            status=status.HTTP_404_NOT_FOUND
        )


@api_view(['POST'])
@permission_classes([permissions.IsAuthenticated])
@extend_schema(
    summary="Lock User Account",
    description="Lock user account temporarily",
    request={
        "type": "object",
        "properties": {
            "duration_minutes": {"type": "integer", "description": "Lock duration in minutes", "default": 30}
        }
    },
    tags=["User Management"]
)
def lock_user_account(request, user_id):
    """Lock user account."""
    try:
        user = User.objects.get(id=user_id)

        # Check permissions
        if not request.user.has_perm('users.change_user'):
            return Response(
                {'error': 'Insufficient permissions to lock accounts'},
                status=status.HTTP_403_FORBIDDEN
            )

        # Prevent self-locking
        if user == request.user:
            return Response(
                {'error': 'Cannot lock your own account'},
                status=status.HTTP_400_BAD_REQUEST
            )

        duration_minutes = request.data.get('duration_minutes', 30)

        try:
            duration_minutes = int(duration_minutes)
            if duration_minutes <= 0:
                raise ValueError("Duration must be positive")
        except (ValueError, TypeError):
            return Response(
                {'error': 'Invalid duration_minutes value'},
                status=status.HTTP_400_BAD_REQUEST
            )

        user.lock_account(duration_minutes)

        return Response({
            'success': True,
            'message': f'Account locked for {duration_minutes} minutes'
        })

    except User.DoesNotExist:
        return Response(
            {'error': 'User not found'},
            status=status.HTTP_404_NOT_FOUND
        )


@api_view(['POST'])
@permission_classes([permissions.IsAuthenticated])
@extend_schema(
    summary="Unlock User Account",
    description="Unlock user account",
    tags=["User Management"]
)
def unlock_user_account(request, user_id):
    """Unlock user account."""
    try:
        user = User.objects.get(id=user_id)

        # Check permissions
        if not request.user.has_perm('users.change_user'):
            return Response(
                {'error': 'Insufficient permissions to unlock accounts'},
                status=status.HTTP_403_FORBIDDEN
            )

        user.unlock_account()

        return Response({
            'success': True,
            'message': 'Account unlocked successfully'
        })

    except User.DoesNotExist:
        return Response(
            {'error': 'User not found'},
            status=status.HTTP_404_NOT_FOUND
        )


@api_view(['POST'])
@permission_classes([permissions.IsAuthenticated])
@extend_schema(
    summary="Reset User Password",
    description="Reset user password (admin only)",
    request={
        "type": "object",
        "properties": {
            "new_password": {"type": "string", "description": "New password"},
            "force_change": {"type": "boolean", "description": "Force password change on next login", "default": True}
        },
        "required": ["new_password"]
    },
    tags=["User Management"]
)
def reset_user_password(request, user_id):
    """Reset user password."""
    try:
        user = User.objects.get(id=user_id)

        # Check permissions
        if not request.user.has_perm('users.change_user'):
            return Response(
                {'error': 'Insufficient permissions to reset passwords'},
                status=status.HTTP_403_FORBIDDEN
            )

        new_password = request.data.get('new_password')
        force_change = request.data.get('force_change', True)

        if not new_password:
            return Response(
                {'error': 'new_password is required'},
                status=status.HTTP_400_BAD_REQUEST
            )

        # Validate password strength
        from django.contrib.auth.password_validation import validate_password
        from django.core.exceptions import ValidationError

        try:
            validate_password(new_password, user)
        except ValidationError as e:
            return Response(
                {'error': 'Password validation failed', 'details': list(e.messages)},
                status=status.HTTP_400_BAD_REQUEST
            )

        # Set new password
        user.set_password(new_password)
        user.force_password_change = force_change
        user.save()

        logger.info(
            "password_reset_by_admin",
            user_id=user.id,
            username=user.username,
            reset_by=request.user.username,
            force_change=force_change,
            correlation_id=getattr(request, 'correlation_id', '')
        )

        return Response({
            'success': True,
            'message': 'Password reset successfully',
            'force_change': force_change
        })

    except User.DoesNotExist:
        return Response(
            {'error': 'User not found'},
            status=status.HTTP_404_NOT_FOUND
        )


@api_view(['GET'])
@permission_classes([permissions.IsAuthenticated])
@extend_schema(
    summary="Get User Activity Summary",
    description="Get user activity and login statistics",
    tags=["User Management"]
)
def get_user_activity(request, user_id):
    """Get user activity summary."""
    try:
        user = User.objects.get(id=user_id)

        # Check permissions
        if not (request.user == user or
                request.user.has_perm('users.view_user') or
                (hasattr(request.user, 'subordinates') and user in request.user.subordinates.all())):
            return Response(
                {'error': 'Insufficient permissions to view user activity'},
                status=status.HTTP_403_FORBIDDEN
            )

        from apps.users.models import UserSession
        from apps.authentication.models import AccessLog
        from datetime import timedelta

        # Get recent activity
        now = timezone.now()
        last_30_days = now - timedelta(days=30)

        # Active sessions
        active_sessions = UserSession.objects.filter(
            user=user,
            is_active=True,
            expires_at__gt=now
        ).count()

        # Recent login count
        recent_logins = AccessLog.objects.filter(
            user=user,
            action='login',
            access_granted=True,
            timestamp__gte=last_30_days
        ).count()

        # Failed login attempts
        failed_logins = AccessLog.objects.filter(
            user=user,
            action='login',
            access_granted=False,
            timestamp__gte=last_30_days
        ).count()

        # Last login info
        last_login_log = AccessLog.objects.filter(
            user=user,
            action='login',
            access_granted=True
        ).order_by('-timestamp').first()

        # Active roles count
        active_roles = UserRole.objects.filter(
            user=user,
            is_active=True
        ).count()

        activity_data = {
            'user': {
                'id': user.id,
                'username': user.username,
                'email': user.email,
                'full_name': user.get_full_name()
            },
            'activity_summary': {
                'active_sessions': active_sessions,
                'recent_logins_30d': recent_logins,
                'failed_logins_30d': failed_logins,
                'active_roles': active_roles,
                'last_login': {
                    'timestamp': last_login_log.timestamp if last_login_log else None,
                    'ip_address': last_login_log.ip_address if last_login_log else None
                },
                'account_status': {
                    'is_active': user.is_active,
                    'is_locked': user.is_account_locked,
                    'force_password_change': user.force_password_change,
                    'password_age_days': user.password_age_days,
                    'last_login': user.last_login
                }
            }
        }

        return Response({
            'success': True,
            'data': activity_data,
            'message': 'User activity retrieved successfully'
        })

    except User.DoesNotExist:
        return Response(
            {'error': 'User not found'},
            status=status.HTTP_404_NOT_FOUND
        )


class BulkUserActionsAPIView(APIView):
    """
    API view for bulk user operations.

    POST: Perform bulk actions on multiple users
    """

    permission_classes = [permissions.IsAuthenticated]

    @extend_schema(
        summary="Bulk User Actions",
        description="Perform bulk actions on multiple users (activate, deactivate, assign role, etc.)",
        request=BulkUserActionSerializer,
        tags=["User Management"]
    )
    def post(self, request):
        """Perform bulk actions on users."""
        # Check permissions
        if not request.user.has_perm('users.change_user'):
            return Response(
                {'error': 'Insufficient permissions for bulk user operations'},
                status=status.HTTP_403_FORBIDDEN
            )

        serializer = BulkUserActionSerializer(data=request.data)
        if not serializer.is_valid():
            return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

        user_ids = serializer.validated_data['user_ids']
        action = serializer.validated_data['action']

        # Get users
        users = User.objects.filter(id__in=user_ids)

        if users.count() != len(user_ids):
            return Response(
                {'error': 'Some users not found'},
                status=status.HTTP_404_NOT_FOUND
            )

        # Prevent actions on self for certain operations
        if request.user.id in user_ids and action in ['deactivate', 'reset_password']:
            return Response(
                {'error': f'Cannot perform {action} on your own account'},
                status=status.HTTP_400_BAD_REQUEST
            )

        try:
            results = self._perform_bulk_action(users, action, serializer.validated_data, request.user)

            logger.info(
                "bulk_user_action_performed",
                action=action,
                user_count=users.count(),
                success_count=results['success_count'],
                performed_by=request.user.username,
                correlation_id=getattr(request, 'correlation_id', '')
            )

            return Response({
                'success': True,
                'data': results,
                'message': f'Bulk {action} operation completed'
            })

        except Exception as e:
            logger.error(
                "bulk_user_action_failed",
                action=action,
                error=str(e),
                correlation_id=getattr(request, 'correlation_id', '')
            )

            return Response(
                {'error': f'Bulk operation failed: {str(e)}'},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )

    def _perform_bulk_action(self, users, action, validated_data, performed_by):
        """Perform the bulk action on users."""
        success_count = 0
        failed_count = 0
        errors = []

        for user in users:
            try:
                if action == 'activate':
                    user.is_active = True
                    user.save()
                    success_count += 1

                elif action == 'deactivate':
                    user.is_active = False
                    user.save()
                    success_count += 1

                elif action == 'reset_password':
                    new_password = validated_data['new_password']
                    force_change = validated_data.get('force_password_change', True)

                    user.set_password(new_password)
                    user.force_password_change = force_change
                    user.save()
                    success_count += 1

                elif action == 'assign_role':
                    from apps.authentication.models import Role
                    from apps.authentication.services import permission_service

                    role = Role.objects.get(id=validated_data['role_id'])

                    # Check if user already has this role
                    if not UserRole.objects.filter(
                            user=user,
                            role=role,
                            scope_type='global',
                            is_active=True
                    ).exists():
                        permission_service.assign_role_to_user(
                            user=user,
                            role=role,
                            assigned_by=performed_by
                        )
                        success_count += 1
                    else:
                        errors.append(f"User {user.username} already has role {role.name}")

                elif action == 'revoke_role':
                    from apps.authentication.models import Role
                    from apps.authentication.services import permission_service

                    role = Role.objects.get(id=validated_data['role_id'])

                    if permission_service.revoke_role_from_user(
                            user=user,
                            role=role,
                            revoked_by=performed_by
                    ):
                        success_count += 1
                    else:
                        errors.append(f"User {user.username} does not have role {role.name}")

            except Exception as e:
                failed_count += 1
                errors.append(f"Failed for user {user.username}: {str(e)}")

        return {
            'success_count': success_count,
            'failed_count': failed_count,
            'total_count': users.count(),
            'errors': errors
        }