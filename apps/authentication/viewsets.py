"""
ViewSets for authentication and RBAC management.

This module provides REST API viewsets for managing roles, permissions,
service accounts, and other authentication-related resources.
"""

import structlog
from django.db.models import Count, Q
from django.utils import timezone
from django_filters.rest_framework import DjangoFilterBackend
from drf_spectacular.utils import extend_schema, extend_schema_view
from rest_framework import viewsets, permissions, status
from rest_framework.decorators import action
from rest_framework.filters import SearchFilter, OrderingFilter
from rest_framework.response import Response

from apps.authentication.models import (
    Role, UserRole, AccessLog, PermissionRequest
)
from apps.authentication.serializers import (
    RoleSerializer, UserRoleSerializer, ServiceAccountSerializer,
    AccessLogSerializer, UserSessionSerializer
)
from apps.shared.pagination import StandardResultsSetPagination
from apps.users.models import ServiceAccount, UserSession

# Configure structured logger
logger = structlog.get_logger(__name__)


@extend_schema_view(
    list=extend_schema(summary="List Roles", tags=["Role Management"]),
    create=extend_schema(summary="Create Role", tags=["Role Management"]),
    retrieve=extend_schema(summary="Get Role", tags=["Role Management"]),
    update=extend_schema(summary="Update Role", tags=["Role Management"]),
    partial_update=extend_schema(summary="Partially Update Role", tags=["Role Management"]),
    destroy=extend_schema(summary="Delete Role", tags=["Role Management"]),
)
class RoleViewSet(viewsets.ModelViewSet):
    """
    ViewSet for managing roles in the RBAC system.

    Provides CRUD operations for roles with permission checking
    and additional role management features.
    """

    queryset = Role.objects.all()
    serializer_class = RoleSerializer
    permission_classes = [permissions.IsAuthenticated]
    pagination_class = StandardResultsSetPagination
    filter_backends = [DjangoFilterBackend, SearchFilter, OrderingFilter]
    filterset_fields = ['service_scope', 'is_active', 'is_system_role']
    search_fields = ['name', 'display_name', 'description']
    ordering_fields = ['name', 'priority', 'created_at']
    ordering = ['-priority', 'name']

    def get_queryset(self):
        """Filter queryset based on user permissions."""
        queryset = super().get_queryset()

        # Add annotations for counts
        queryset = queryset.annotate(
            permissions_count=Count('permissions'),
            users_count=Count('user_assignments')
        )

        # Filter based on user permissions
        if not self.request.user.is_superuser:
            # Non-superusers can only see roles they have permission to manage
            # or roles in services they have access to
            if hasattr(self.request.user, 'user_roles'):
                accessible_services = self.request.user.user_roles.values_list(
                    'role__service_scope', flat=True
                ).distinct()
                queryset = queryset.filter(
                    Q(service_scope__in=accessible_services) |
                    Q(service_scope='') |
                    Q(service_scope__isnull=True)
                )

        return queryset

    def perform_create(self, serializer):
        """Create role with audit logging."""
        role = serializer.save(created_by=self.request.user)

        logger.info(
            "role_created",
            role_id=role.id,
            role_name=role.name,
            created_by=self.request.user.username,
            correlation_id=getattr(self.request, 'correlation_id', '')
        )

    def perform_update(self, serializer):
        """Update role with audit logging."""
        old_name = serializer.instance.name
        role = serializer.save()

        logger.info(
            "role_updated",
            role_id=role.id,
            old_name=old_name,
            new_name=role.name,
            updated_by=self.request.user.username,
            correlation_id=getattr(self.request, 'correlation_id', '')
        )

    def perform_destroy(self, instance):
        """Delete role with audit logging."""
        role_name = instance.name
        role_id = instance.id

        # Check if role can be deleted (not system role and no active assignments)
        if instance.is_system_role:
            return Response(
                {'error': 'Cannot delete system role'},
                status=status.HTTP_400_BAD_REQUEST
            )

        active_assignments = UserRole.objects.filter(
            role=instance,
            is_active=True
        ).count()

        if active_assignments > 0:
            return Response(
                {'error': f'Cannot delete role with {active_assignments} active assignments'},
                status=status.HTTP_400_BAD_REQUEST
            )

        instance.delete()

        logger.info(
            "role_deleted",
            role_id=role_id,
            role_name=role_name,
            deleted_by=self.request.user.username,
            correlation_id=getattr(self.request, 'correlation_id', '')
        )

    @extend_schema(
        summary="Get Role Permissions",
        description="Get all permissions for a specific role"
    )
    @action(detail=True, methods=['get'])
    def permissions(self, request, pk=None):
        """Get all permissions for a role."""
        role = self.get_object()
        permissions = role.get_all_permissions()

        permission_data = []
        for perm in permissions:
            permission_data.append({
                'id': perm.id,
                'codename': perm.codename,
                'name': perm.name,
                'service': perm.content_type.app_label,
                'model': perm.content_type.model
            })

        return Response({
            'role': role.name,
            'permissions': permission_data,
            'total_count': len(permission_data)
        })

    @extend_schema(
        summary="Get Role Users",
        description="Get all users assigned to a specific role"
    )
    @action(detail=True, methods=['get'])
    def users(self, request, pk=None):
        """Get all users assigned to a role."""
        role = self.get_object()
        user_roles = UserRole.objects.filter(
            role=role,
            is_active=True
        ).select_related('user')

        users_data = []
        for user_role in user_roles:
            users_data.append({
                'user_id': user_role.user.id,
                'username': user_role.user.username,
                'email': user_role.user.email,
                'full_name': user_role.user.get_full_name(),
                'scope_type': user_role.scope_type,
                'scope_id': user_role.scope_id,
                'assigned_at': user_role.assigned_at,
                'expires_at': user_role.expires_at
            })

        return Response({
            'role': role.name,
            'users': users_data,
            'total_count': len(users_data)
        })


@extend_schema_view(
    list=extend_schema(summary="List User Role Assignments", tags=["User Role Management"]),
    create=extend_schema(summary="Assign Role to User", tags=["User Role Management"]),
    retrieve=extend_schema(summary="Get User Role Assignment", tags=["User Role Management"]),
    update=extend_schema(summary="Update User Role Assignment", tags=["User Role Management"]),
    destroy=extend_schema(summary="Revoke Role from User", tags=["User Role Management"]),
)
class UserRoleViewSet(viewsets.ModelViewSet):
    """
    ViewSet for managing user role assignments.

    Handles role assignments to users with context and audit logging.
    """

    queryset = UserRole.objects.all()
    serializer_class = UserRoleSerializer
    permission_classes = [permissions.IsAuthenticated]
    pagination_class = StandardResultsSetPagination
    filter_backends = [DjangoFilterBackend, SearchFilter, OrderingFilter]
    filterset_fields = ['user', 'role', 'scope_type', 'is_active']
    search_fields = ['user__username', 'user__email', 'role__name']
    ordering_fields = ['assigned_at', 'expires_at']
    ordering = ['-assigned_at']

    def get_queryset(self):
        """Filter queryset based on user permissions."""
        queryset = super().get_queryset().select_related(
            'user', 'role', 'assigned_by'
        )

        # Filter based on user permissions
        if not self.request.user.is_superuser:
            # Users can see their own role assignments
            # Managers can see their subordinates' assignments
            # HR/Admin can see all assignments based on permissions

            user_filter = Q(user=self.request.user)

            # Add subordinates if user is a manager
            if hasattr(self.request.user, 'subordinates'):
                subordinate_ids = self.request.user.subordinates.values_list('id', flat=True)
                user_filter |= Q(user__id__in=subordinate_ids)

            # Check for user management permissions
            if self.request.user.has_perm('authentication.view_userrole'):
                # User has permission to view all role assignments
                pass
            else:
                queryset = queryset.filter(user_filter)

        return queryset

    def perform_create(self, serializer):
        """Create user role assignment with audit logging."""
        user_role = serializer.save(assigned_by=self.request.user)

        logger.info(
            "user_role_assigned",
            user_role_id=user_role.id,
            user_id=user_role.user.id,
            username=user_role.user.username,
            role_name=user_role.role.name,
            scope_type=user_role.scope_type,
            scope_id=user_role.scope_id,
            assigned_by=self.request.user.username,
            correlation_id=getattr(self.request, 'correlation_id', '')
        )

    def perform_destroy(self, instance):
        """Revoke user role assignment."""
        # Instead of deleting, mark as inactive
        instance.is_active = False
        instance.save()

        logger.info(
            "user_role_revoked",
            user_role_id=instance.id,
            user_id=instance.user.id,
            username=instance.user.username,
            role_name=instance.role.name,
            revoked_by=self.request.user.username,
            correlation_id=getattr(self.request, 'correlation_id', '')
        )

    @extend_schema(
        summary="Activate User Role Assignment",
        description="Reactivate a revoked user role assignment"
    )
    @action(detail=True, methods=['post'])
    def activate(self, request, pk=None):
        """Reactivate user role assignment."""
        user_role = self.get_object()

        if user_role.is_active:
            return Response(
                {'error': 'Role assignment is already active'},
                status=status.HTTP_400_BAD_REQUEST
            )

        user_role.is_active = True
        user_role.assigned_by = request.user
        user_role.assigned_at = timezone.now()
        user_role.save()

        logger.info(
            "user_role_reactivated",
            user_role_id=user_role.id,
            user_id=user_role.user.id,
            username=user_role.user.username,
            role_name=user_role.role.name,
            reactivated_by=request.user.username,
            correlation_id=getattr(request, 'correlation_id', '')
        )

        return Response({'message': 'Role assignment reactivated successfully'})


@extend_schema_view(
    list=extend_schema(summary="List Service Accounts", tags=["Service Account Management"]),
    create=extend_schema(summary="Create Service Account", tags=["Service Account Management"]),
    retrieve=extend_schema(summary="Get Service Account", tags=["Service Account Management"]),
    update=extend_schema(summary="Update Service Account", tags=["Service Account Management"]),
    destroy=extend_schema(summary="Delete Service Account", tags=["Service Account Management"]),
)
class ServiceAccountViewSet(viewsets.ModelViewSet):
    """
    ViewSet for managing service accounts.

    Handles service account creation, management, and token generation.
    """

    queryset = ServiceAccount.objects.all()
    serializer_class = ServiceAccountSerializer
    permission_classes = [permissions.IsAuthenticated]
    pagination_class = StandardResultsSetPagination
    filter_backends = [DjangoFilterBackend, SearchFilter, OrderingFilter]
    filterset_fields = ['service_name', 'is_active']
    search_fields = ['name', 'service_name', 'description']
    ordering_fields = ['name', 'created_at', 'last_used']
    ordering = ['-created_at']

    def get_queryset(self):
        """Filter queryset based on user permissions."""
        queryset = super().get_queryset().select_related('created_by')

        # Only users with service account management permissions can see all
        if not self.request.user.has_perm('users.view_serviceaccount'):
            # Users can only see service accounts they created
            queryset = queryset.filter(created_by=self.request.user)

        return queryset

    def perform_create(self, serializer):
        """Create service account with audit logging."""
        service_account = serializer.save(created_by=self.request.user)

        logger.info(
            "service_account_created",
            service_account_id=service_account.id,
            service_account_name=service_account.name,
            service_name=service_account.service_name,
            created_by=self.request.user.username,
            correlation_id=getattr(self.request, 'correlation_id', '')
        )

    @extend_schema(
        summary="Generate Service Token",
        description="Generate JWT token for service account"
    )
    @action(detail=True, methods=['post'])
    def generate_token(self, request, pk=None):
        """Generate JWT token for service account."""
        service_account = self.get_object()

        if not service_account.is_active:
            return Response(
                {'error': 'Service account is inactive'},
                status=status.HTTP_400_BAD_REQUEST
            )

        if service_account.is_expired:
            return Response(
                {'error': 'Service account has expired'},
                status=status.HTTP_400_BAD_REQUEST
            )

        # Generate token
        from apps.authentication.services import jwt_service

        try:
            token = jwt_service.generate_service_token(
                service_account=service_account,
                ip_address=self._get_client_ip(request)
            )

            logger.info(
                "service_token_generated_via_api",
                service_account_id=service_account.id,
                service_account_name=service_account.name,
                requested_by=request.user.username,
                correlation_id=getattr(request, 'correlation_id', '')
            )

            return Response({
                'token': token,
                'token_type': 'Bearer',
                'expires_in': jwt_service.service_token_lifetime,
                'scopes': service_account.scopes
            })

        except Exception as e:
            logger.error(
                "service_token_generation_failed",
                service_account_id=service_account.id,
                error=str(e),
                correlation_id=getattr(request, 'correlation_id', '')
            )

            return Response(
                {'error': 'Token generation failed'},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )

    @extend_schema(
        summary="Regenerate API Key",
        description="Generate new API key for service account"
    )
    @action(detail=True, methods=['post'])
    def regenerate_api_key(self, request, pk=None):
        """Regenerate API key for service account."""
        import uuid

        service_account = self.get_object()
        old_api_key = str(service_account.api_key)

        # Generate new API key
        service_account.api_key = uuid.uuid4()
        service_account.save()

        logger.info(
            "service_account_api_key_regenerated",
            service_account_id=service_account.id,
            service_account_name=service_account.name,
            regenerated_by=request.user.username,
            correlation_id=getattr(request, 'correlation_id', '')
        )

        return Response({
            'message': 'API key regenerated successfully',
            'new_api_key': str(service_account.api_key)
        })

    def _get_client_ip(self, request) -> str:
        """Extract client IP address from request."""
        x_forwarded_for = request.META.get('HTTP_X_FORWARDED_FOR')
        if x_forwarded_for:
            ip = x_forwarded_for.split(',')[0].strip()
        else:
            ip = request.META.get('REMOTE_ADDR', '0.0.0.0')
        return ip


@extend_schema_view(
    list=extend_schema(summary="List Access Logs", tags=["Audit & Logging"]),
    retrieve=extend_schema(summary="Get Access Log Entry", tags=["Audit & Logging"]),
)
class AccessLogViewSet(viewsets.ReadOnlyModelViewSet):
    """
    ViewSet for viewing access logs.

    Provides read-only access to audit logs for security and compliance.
    """

    queryset = AccessLog.objects.all()
    serializer_class = AccessLogSerializer
    permission_classes = [permissions.IsAuthenticated]
    pagination_class = StandardResultsSetPagination
    filter_backends = [DjangoFilterBackend, SearchFilter, OrderingFilter]
    filterset_fields = [
        'user', 'service_account', 'service_name',
        'access_granted', 'action'
    ]
    search_fields = [
        'user__username', 'service_account__name',
        'action', 'resource', 'ip_address'
    ]
    ordering_fields = ['timestamp']
    ordering = ['-timestamp']

    def get_queryset(self):
        """Filter queryset based on user permissions."""
        queryset = super().get_queryset().select_related(
            'user', 'service_account'
        )

        # Only users with audit log viewing permissions can see all logs
        if not self.request.user.has_perm('authentication.view_accesslog'):
            # Users can only see their own access logs
            queryset = queryset.filter(user=self.request.user)

        return queryset


@extend_schema_view(
    list=extend_schema(summary="List User Sessions", tags=["Session Management"]),
    retrieve=extend_schema(summary="Get User Session", tags=["Session Management"]),
    destroy=extend_schema(summary="Terminate User Session", tags=["Session Management"]),
)
class UserSessionViewSet(viewsets.ModelViewSet):
    """
    ViewSet for managing user sessions.

    Handles user session monitoring and termination.
    """

    queryset = UserSession.objects.all()
    serializer_class = UserSessionSerializer
    permission_classes = [permissions.IsAuthenticated]
    pagination_class = StandardResultsSetPagination
    filter_backends = [DjangoFilterBackend, SearchFilter, OrderingFilter]
    filterset_fields = ['user', 'is_active']
    search_fields = ['user__username', 'ip_address']
    ordering_fields = ['created_at', 'last_activity']
    ordering = ['-last_activity']
    http_method_names = ['get', 'patch', 'delete']

    def get_queryset(self):
        """Filter queryset based on user permissions."""
        queryset = super().get_queryset().select_related('user')

        # Users can see their own sessions
        # Admins can see all sessions
        if not self.request.user.has_perm('users.view_usersession'):
            queryset = queryset.filter(user=self.request.user)

        return queryset

    def perform_destroy(self, instance):
        """Terminate user session."""
        instance.terminate()

        logger.info(
            "user_session_terminated_via_api",
            session_id=instance.id,
            user_id=instance.user.id,
            terminated_by=self.request.user.username,
            correlation_id=getattr(self.request, 'correlation_id', '')
        )

    @extend_schema(
        summary="Terminate All User Sessions",
        description="Terminate all active sessions for a user"
    )
    @action(detail=False, methods=['post'])
    def terminate_all(self, request):
        """Terminate all active sessions for the current user."""
        terminated_count = UserSession.objects.filter(
            user=request.user,
            is_active=True
        ).update(is_active=False)

        logger.info(
            "all_user_sessions_terminated",
            user_id=request.user.id,
            terminated_count=terminated_count,
            correlation_id=getattr(request, 'correlation_id', '')
        )

        return Response({
            'message': f'Terminated {terminated_count} active sessions'
        })


@extend_schema_view(
    list=extend_schema(summary="List Permission Requests", tags=["Permission Management"]),
    create=extend_schema(summary="Create Permission Request", tags=["Permission Management"]),
    retrieve=extend_schema(summary="Get Permission Request", tags=["Permission Management"]),
)
class PermissionRequestViewSet(viewsets.ModelViewSet):
    """
    ViewSet for managing permission requests.

    Handles permission request workflows and approvals.
    """

    queryset = PermissionRequest.objects.all()
    permission_classes = [permissions.IsAuthenticated]
    pagination_class = StandardResultsSetPagination
    filter_backends = [DjangoFilterBackend, SearchFilter, OrderingFilter]
    filterset_fields = ['status', 'requester', 'target_user', 'role']
    search_fields = ['justification', 'approval_notes']
    ordering_fields = ['created_at', 'updated_at']
    ordering = ['-created_at']
    http_method_names = ['get', 'post', 'patch']

    def get_queryset(self):
        """Filter queryset based on user permissions."""
        queryset = super().get_queryset().select_related(
            'requester', 'target_user', 'role', 'approved_by'
        )

        # Users can see requests they made or requests for them
        # Approvers can see requests they can approve
        if not self.request.user.has_perm('authentication.view_permissionrequest'):
            user_filter = Q(requester=self.request.user) | Q(target_user=self.request.user)

            # Add requests user can approve (based on role hierarchy or permissions)
            if self.request.user.has_perm('authentication.change_permissionrequest'):
                # User can approve requests - show pending requests
                user_filter |= Q(status='pending')

            queryset = queryset.filter(user_filter)

        return queryset

    @extend_schema(
        summary="Approve Permission Request",
        description="Approve a pending permission request"
    )
    @action(detail=True, methods=['post'])
    def approve(self, request, pk=None):
        """Approve permission request."""
        permission_request = self.get_object()

        if permission_request.status != 'pending':
            return Response(
                {'error': 'Only pending requests can be approved'},
                status=status.HTTP_400_BAD_REQUEST
            )

        notes = request.data.get('notes', '')

        try:
            permission_request.approve(request.user, notes)

            return Response({
                'message': 'Permission request approved successfully'
            })

        except Exception as e:
            logger.error(
                "permission_request_approval_failed",
                request_id=str(permission_request.id),
                error=str(e),
                correlation_id=getattr(request, 'correlation_id', '')
            )

            return Response(
                {'error': 'Failed to approve permission request'},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )

    @extend_schema(
        summary="Reject Permission Request",
        description="Reject a pending permission request"
    )
    @action(detail=True, methods=['post'])
    def reject(self, request, pk=None):
        """Reject permission request."""
        permission_request = self.get_object()

        if permission_request.status != 'pending':
            return Response(
                {'error': 'Only pending requests can be rejected'},
                status=status.HTTP_400_BAD_REQUEST
            )

        notes = request.data.get('notes', '')

        if not notes:
            return Response(
                {'error': 'Rejection reason is required'},
                status=status.HTTP_400_BAD_REQUEST
            )

        permission_request.reject(request.user, notes)

        return Response({
            'message': 'Permission request rejected successfully'
        })
