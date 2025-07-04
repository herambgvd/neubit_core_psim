"""
ViewSets for user management.

This module provides REST API viewsets for managing users and user-related
resources in the Core Platform.
"""

from django.contrib.auth import get_user_model
from django.db.models import Q, Count
from rest_framework import viewsets, permissions, status
from rest_framework.decorators import action
from rest_framework.response import Response
from rest_framework.filters import SearchFilter, OrderingFilter
from django_filters.rest_framework import DjangoFilterBackend
from drf_spectacular.utils import extend_schema, extend_schema_view

import structlog

from apps.users.serializers import UserSerializer, UserCreateSerializer
from apps.authentication.serializers import UserRoleSerializer
from apps.authentication.models import UserRole
from apps.shared.pagination import StandardResultsSetPagination

# Configure structured logger
logger = structlog.get_logger(__name__)

User = get_user_model()


@extend_schema_view(
    list=extend_schema(summary="List Users", tags=["User Management"]),
    create=extend_schema(summary="Create User", tags=["User Management"]),
    retrieve=extend_schema(summary="Get User", tags=["User Management"]),
    update=extend_schema(summary="Update User", tags=["User Management"]),
    partial_update=extend_schema(summary="Partially Update User", tags=["User Management"]),
    destroy=extend_schema(summary="Delete User", tags=["User Management"]),
)
class UserViewSet(viewsets.ModelViewSet):
    """
    ViewSet for user management.

    Provides CRUD operations for users with proper permission checking
    and additional user management features.
    """

    queryset = User.objects.all()
    serializer_class = UserSerializer
    permission_classes = [permissions.IsAuthenticated]
    pagination_class = StandardResultsSetPagination
    filter_backends = [DjangoFilterBackend, SearchFilter, OrderingFilter]
    filterset_fields = [
        'is_active', 'is_staff', 'is_superuser', 'department',
        'is_service_account'
    ]
    search_fields = [
        'username', 'email', 'first_name', 'last_name',
        'employee_id', 'department', 'job_title'
    ]
    ordering_fields = [
        'username', 'email', 'first_name', 'last_name',
        'created_at', 'last_login'
    ]
    ordering = ['username']

    def get_queryset(self):
        """Filter queryset based on user permissions."""
        queryset = super().get_queryset().select_related('profile', 'manager')

        # Exclude service accounts from regular user management
        # unless specifically requested
        if not self.request.query_params.get('include_service_accounts'):
            queryset = queryset.filter(is_service_account=False)

        # Filter based on user permissions
        if not self.request.user.is_superuser:
            # Non-superusers have limited access
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

        return queryset

    def get_serializer_class(self):
        """Return appropriate serializer based on action."""
        if self.action == 'create':
            return UserCreateSerializer
        return self.serializer_class

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

    def perform_update(self, serializer):
        """Update user with audit logging."""
        old_data = {
            'username': serializer.instance.username,
            'email': serializer.instance.email,
            'is_active': serializer.instance.is_active,
        }

        user = serializer.save()

        # Log significant changes
        changes = []
        for field, old_value in old_data.items():
            new_value = getattr(user, field)
            if old_value != new_value:
                changes.append(f"{field}: {old_value} -> {new_value}")

        if changes:
            logger.info(
                "user_updated_via_api",
                user_id=user.id,
                username=user.username,
                changes=changes,
                updated_by=self.request.user.username,
                correlation_id=getattr(self.request, 'correlation_id', '')
            )

    def perform_destroy(self, instance):
        """Soft delete user instead of hard delete."""
        # Instead of deleting, deactivate the user
        instance.is_active = False
        instance.save()

        logger.info(
            "user_deactivated_via_api",
            user_id=instance.id,
            username=instance.username,
            deactivated_by=self.request.user.username,
            correlation_id=getattr(self.request, 'correlation_id', '')
        )

    @extend_schema(
        summary="Get User Roles",
        description="Get all roles assigned to a specific user"
    )
    @action(detail=True, methods=['get'])
    def roles(self, request, pk=None):
        """Get user's role assignments."""
        user = self.get_object()

        user_roles = UserRole.objects.filter(
            user=user,
            is_active=True
        ).select_related('role', 'assigned_by')

        serializer = UserRoleSerializer(user_roles, many=True)

        return Response({
            'user': {
                'id': user.id,
                'username': user.username,
                'email': user.email
            },
            'roles': serializer.data,
            'total_count': user_roles.count()
        })

    @extend_schema(
        summary="Assign Role to User",
        description="Assign a role to the user"
    )
    @action(detail=True, methods=['post'])
    def assign_role(self, request, pk=None):
        """Assign role to user."""
        user = self.get_object()

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
                'message': 'Role assigned successfully',
                'user_role': serializer.data
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

    @extend_schema(
        summary="Revoke Role from User",
        description="Revoke a role assignment from the user"
    )
    @action(detail=True, methods=['post'])
    def revoke_role(self, request, pk=None):
        """Revoke role from user."""
        user = self.get_object()

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
                'message': 'Role revoked successfully'
            })
        else:
            return Response(
                {'error': 'Role assignment not found or already inactive'},
                status=status.HTTP_404_NOT_FOUND
            )

    @extend_schema(
        summary="Get User Permissions",
        description="Get all permissions for a specific user"
    )
    @action(detail=True, methods=['get'])
    def permissions(self, request, pk=None):
        """Get user's permissions."""
        user = self.get_object()
        service_name = request.query_params.get('service_name')

        from apps.authentication.services import permission_service

        permissions = permission_service.get_user_permissions(
            user=user,
            service_name=service_name
        )

        return Response({
            'user': {
                'id': user.id,
                'username': user.username,
                'email': user.email
            },
            'permissions': permissions,
            'service_filter': service_name,
            'total_count': len(permissions)
        })

    @extend_schema(
        summary="Lock User Account",
        description="Lock user account temporarily"
    )
    @action(detail=True, methods=['post'])
    def lock_account(self, request, pk=None):
        """Lock user account."""
        user = self.get_object()

        # Check permissions
        if not request.user.has_perm('users.change_user'):
            return Response(
                {'error': 'Insufficient permissions to lock accounts'},
                status=status.HTTP_403_FORBIDDEN
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
            'message': f'Account locked for {duration_minutes} minutes'
        })

    @extend_schema(
        summary="Unlock User Account",
        description="Unlock user account"
    )
    @action(detail=True, methods=['post'])
    def unlock_account(self, request, pk=None):
        """Unlock user account."""
        user = self.get_object()

        # Check permissions
        if not request.user.has_perm('users.change_user'):
            return Response(
                {'error': 'Insufficient permissions to unlock accounts'},
                status=status.HTTP_403_FORBIDDEN
            )

        user.unlock_account()

        return Response({
            'message': 'Account unlocked successfully'
        })

    @extend_schema(
        summary="Reset User Password",
        description="Reset user password (admin only)"
    )
    @action(detail=True, methods=['post'])
    def reset_password(self, request, pk=None):
        """Reset user password."""
        user = self.get_object()

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
            'message': 'Password reset successfully',
            'force_change': force_change
        })

    @extend_schema(
        summary="Get User Activity Summary",
        description="Get user activity and login statistics"
    )
    @action(detail=True, methods=['get'])
    def activity_summary(self, request, pk=None):
        """Get user activity summary."""
        user = self.get_object()

        from apps.users.models import UserSession
        from apps.authentication.models import AccessLog
        from django.utils import timezone
        from datetime import timedelta

        # Get recent activity
        now = timezone.now()
        last_30_days = now - timedelta(days=30)

        # Active sessions
        active_sessions = UserSession.objects.filter(
            user=user,
            is_active=True
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

        return Response({
            'user': {
                'id': user.id,
                'username': user.username,
                'email': user.email
            },
            'activity_summary': {
                'active_sessions': active_sessions,
                'recent_logins_30d': recent_logins,
                'failed_logins_30d': failed_logins,
                'last_login': {
                    'timestamp': last_login_log.timestamp if last_login_log else None,
                    'ip_address': last_login_log.ip_address if last_login_log else None
                },
                'account_status': {
                    'is_active': user.is_active,
                    'is_locked': user.is_account_locked,
                    'force_password_change': user.force_password_change,
                    'password_age_days': user.password_age_days
                }
            }
        })