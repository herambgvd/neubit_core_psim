"""
Authentication services for Core Platform Service.

This module provides comprehensive authentication services including
JWT token management, service-to-service authentication, and
RBAC permission validation.
"""

from datetime import datetime
from typing import Dict, Any, Optional, List

import structlog
from django.contrib.auth import get_user_model
from django.contrib.auth.models import Permission
from django.utils import timezone

from apps.authentication.models import Role, UserRole, AccessLog
from apps.users.models import ServiceAccount

# Configure structured logger
logger = structlog.get_logger(__name__)

User = get_user_model()


class PermissionService:
    """
    Permission and RBAC service.

    Handles role-based access control, permission checking,
    and authorization for users and services.
    """

    def __init__(self):
        """Initialize permission service."""
        pass

    def check_user_permission(
            self,
            user: User,
            permission: str,
            service_name: str,
            resource_id: Optional[str] = None,
            context: Optional[Dict[str, Any]] = None
    ) -> Dict[str, Any]:
        """
        Check if user has specific permission.

        Args:
            user: User instance
            permission: Permission codename
            service_name: Service name
            resource_id: Optional resource identifier
            context: Additional context (location, etc.)

        Returns:
            Dictionary with permission check results
        """
        if user.is_superuser:
            return {
                'granted': True,
                'reason': 'superuser',
                'roles': [],
                'permissions': []
            }

        # Get user's effective roles for the context
        effective_roles = self._get_user_effective_roles(user, context)

        # Check permission through roles
        granted_roles = []
        granted_permissions = []

        for user_role in effective_roles:
            if user_role.role.has_permission(permission, service_name):
                granted_roles.append(user_role.role.name)
                # Get the specific permissions that grant this access
                role_permissions = user_role.role.get_all_permissions().filter(
                    codename=permission,
                    content_type__app_label=service_name
                )
                granted_permissions.extend([p.codename for p in role_permissions])

        # Check direct user permissions
        direct_permission = user.user_permissions.filter(
            codename=permission,
            content_type__app_label=service_name
        ).first()

        if direct_permission:
            granted_permissions.append(direct_permission.codename)

        granted = bool(granted_roles or direct_permission)

        # Log access attempt
        self._log_access_attempt(
            user=user,
            action=permission,
            resource=resource_id or service_name,
            service_name=service_name,
            permission_required=permission,
            access_granted=granted,
            denial_reason="" if granted else "insufficient_permissions",
            additional_context=context or {}
        )

        return {
            'granted': granted,
            'reason': 'role_permission' if granted_roles else ('direct_permission' if direct_permission else 'denied'),
            'roles': granted_roles,
            'permissions': list(set(granted_permissions))
        }

    def check_service_permission(
            self,
            service_account: ServiceAccount,
            permission: str,
            resource_id: Optional[str] = None
    ) -> Dict[str, Any]:
        """
        Check if service account has specific permission.

        Args:
            service_account: Service account instance
            permission: Permission/scope to check
            resource_id: Optional resource identifier

        Returns:
            Dictionary with permission check results
        """
        if not service_account.is_active or service_account.is_expired:
            return {
                'granted': False,
                'reason': 'service_account_inactive_or_expired',
                'scopes': []
            }

        # Check if service has the required scope
        has_scope = service_account.has_scope(permission)

        # Log access attempt
        self._log_access_attempt(
            service_account=service_account,
            action=permission,
            resource=resource_id or service_account.service_name,
            service_name=service_account.service_name,
            permission_required=permission,
            access_granted=has_scope,
            denial_reason="" if has_scope else "insufficient_scope"
        )

        return {
            'granted': has_scope,
            'reason': 'scope_granted' if has_scope else 'scope_denied',
            'scopes': service_account.scopes
        }

    def get_user_permissions(
            self,
            user: User,
            service_name: Optional[str] = None,
            context: Optional[Dict[str, Any]] = None
    ) -> List[str]:
        """
        Get all permissions for a user.

        Args:
            user: User instance
            service_name: Optional service name filter
            context: Additional context

        Returns:
            List of permission codenames
        """
        if user.is_superuser:
            # Superuser has all permissions
            if service_name:
                permissions = Permission.objects.filter(
                    content_type__app_label=service_name
                )
            else:
                permissions = Permission.objects.all()
            return [f"{p.content_type.app_label}.{p.codename}" for p in permissions]

        permission_set = set()

        # Get permissions from roles
        effective_roles = self._get_user_effective_roles(user, context)
        for user_role in effective_roles:
            role_permissions = user_role.role.get_all_permissions()
            if service_name:
                role_permissions = role_permissions.filter(
                    content_type__app_label=service_name
                )

            for perm in role_permissions:
                permission_set.add(f"{perm.content_type.app_label}.{perm.codename}")

        # Get direct user permissions
        direct_permissions = user.user_permissions.all()
        if service_name:
            direct_permissions = direct_permissions.filter(
                content_type__app_label=service_name
            )

        for perm in direct_permissions:
            permission_set.add(f"{perm.content_type.app_label}.{perm.codename}")

        return list(permission_set)

    def assign_role_to_user(
            self,
            user: User,
            role: Role,
            assigned_by: User,
            scope_type: str = 'global',
            scope_id: str = '',
            expires_at: Optional[datetime] = None
    ) -> UserRole:
        """
        Assign role to user.

        Args:
            user: User to assign role to
            role: Role to assign
            assigned_by: User performing the assignment
            scope_type: Scope type for the assignment
            scope_id: Scope ID for the assignment
            expires_at: Optional expiration time

        Returns:
            UserRole instance
        """
        user_role, created = UserRole.objects.get_or_create(
            user=user,
            role=role,
            scope_type=scope_type,
            scope_id=scope_id,
            defaults={
                'assigned_by': assigned_by,
                'expires_at': expires_at,
                'is_active': True,
            }
        )

        if not created and not user_role.is_active:
            # Reactivate existing assignment
            user_role.is_active = True
            user_role.assigned_by = assigned_by
            user_role.assigned_at = timezone.now()
            user_role.expires_at = expires_at
            user_role.save()

        logger.info(
            "role_assigned_to_user",
            user_id=user.id,
            username=user.username,
            role=role.name,
            assigned_by=assigned_by.username,
            scope_type=scope_type,
            scope_id=scope_id
        )

        return user_role

    def revoke_role_from_user(
            self,
            user: User,
            role: Role,
            revoked_by: User,
            scope_type: str = 'global',
            scope_id: str = ''
    ) -> bool:
        """
        Revoke role from user.

        Args:
            user: User to revoke role from
            role: Role to revoke
            revoked_by: User performing the revocation
            scope_type: Scope type
            scope_id: Scope ID

        Returns:
            True if role was revoked
        """
        try:
            user_role = UserRole.objects.get(
                user=user,
                role=role,
                scope_type=scope_type,
                scope_id=scope_id,
                is_active=True
            )

            user_role.is_active = False
            user_role.save()

            logger.info(
                "role_revoked_from_user",
                user_id=user.id,
                username=user.username,
                role=role.name,
                revoked_by=revoked_by.username,
                scope_type=scope_type,
                scope_id=scope_id
            )

            return True

        except UserRole.DoesNotExist:
            logger.warning(
                "role_revocation_failed_not_found",
                user_id=user.id,
                role=role.name,
                scope_type=scope_type,
                scope_id=scope_id
            )
            return False

    def _get_user_effective_roles(
            self,
            user: User,
            context: Optional[Dict[str, Any]] = None
    ) -> List[UserRole]:
        """
        Get user's effective roles based on context.

        Args:
            user: User instance
            context: Context information (location, etc.)

        Returns:
            List of effective UserRole instances
        """
        # Get all active role assignments for user
        user_roles = UserRole.objects.filter(
            user=user,
            is_active=True
        ).select_related('role')

        # Filter by context if provided
        if context:
            location_id = context.get('location_id')
            department = context.get('department')

            # Global roles are always effective
            effective_roles = list(user_roles.filter(scope_type='global'))

            # Add location-specific roles if location context provided
            if location_id:
                effective_roles.extend(
                    user_roles.filter(
                        scope_type='location',
                        scope_id=str(location_id)
                    )
                )

            # Add department-specific roles if department context provided
            if department:
                effective_roles.extend(
                    user_roles.filter(
                        scope_type='department',
                        scope_id=department
                    )
                )
        else:
            # No context, return all active roles
            effective_roles = list(user_roles)

        # Filter out expired roles
        now = timezone.now()
        effective_roles = [
            role for role in effective_roles
            if not role.expires_at or role.expires_at > now
        ]

        return effective_roles

    def _log_access_attempt(
            self,
            action: str,
            resource: str,
            service_name: str,
            permission_required: str,
            access_granted: bool,
            user: Optional[User] = None,
            service_account: Optional[ServiceAccount] = None,
            denial_reason: str = "",
            ip_address: str = "0.0.0.0",
            user_agent: str = "",
            additional_context: Optional[Dict[str, Any]] = None
    ):
        """Log access attempt for audit purposes."""
        try:
            AccessLog.objects.create(
                user=user,
                service_account=service_account,
                action=action,
                resource=resource,
                service_name=service_name,
                permission_required=permission_required,
                access_granted=access_granted,
                denial_reason=denial_reason,
                ip_address=ip_address,
                user_agent=user_agent,
                additional_context=additional_context or {}
            )
        except Exception as e:
            logger.error("access_log_creation_failed", error=str(e))



