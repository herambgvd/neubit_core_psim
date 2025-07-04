"""
Django admin configuration for Authentication and RBAC.

This module provides comprehensive admin interfaces for roles, permissions,
user role assignments, access logs, and permission requests.
"""

from django.contrib import admin
from django.contrib.auth.models import Permission
from django.utils.html import format_html
from django.urls import reverse
from django.utils.safestring import mark_safe
from django.db.models import Count
from django.utils import timezone

from apps.authentication.models import (
    Role, RolePermission, UserRole, ExtendedPermission,
    PermissionRequest, AccessLog
)


class RolePermissionInline(admin.TabularInline):
    """Inline admin for role permissions."""
    model = RolePermission
    extra = 0
    fields = ('permission', 'granted_by', 'granted_at', 'expires_at', 'conditions')
    readonly_fields = ('granted_at',)

    def get_queryset(self, request):
        """Optimize queryset with select_related."""
        return super().get_queryset(request).select_related('permission', 'granted_by')


@admin.register(Role)
class RoleAdmin(admin.ModelAdmin):
    """Admin for roles."""

    inlines = [RolePermissionInline]

    list_display = (
        'name', 'display_name', 'service_scope', 'parent_role',
        'is_active', 'is_system_role', 'priority', 'permissions_count',
        'users_count', 'created_at'
    )

    list_filter = (
        'is_active', 'is_system_role', 'service_scope', 'priority', 'created_at'
    )

    search_fields = (
        'name', 'display_name', 'description', 'service_scope'
    )

    ordering = ('-priority', 'name')

    readonly_fields = ('created_at', 'updated_at')

    fieldsets = (
        (None, {
            'fields': ('name', 'display_name', 'description')
        }),
        ('Hierarchy', {
            'fields': ('parent_role', 'priority')
        }),
        ('Configuration', {
            'fields': ('service_scope', 'is_active', 'is_system_role')
        }),
        ('Audit Information', {
            'fields': ('created_by', 'created_at', 'updated_at'),
            'classes': ('collapse',)
        }),
    )

    def get_queryset(self, request):
        """Optimize queryset with annotations."""
        return super().get_queryset(request).select_related(
            'parent_role', 'created_by'
        ).annotate(
            permissions_count=Count('permissions'),
            users_count=Count('user_assignments')
        )

    def permissions_count(self, obj):
        """Get count of permissions."""
        return obj.permissions_count

    permissions_count.short_description = 'Permissions'
    permissions_count.admin_order_field = 'permissions_count'

    def users_count(self, obj):
        """Get count of users with this role."""
        count = obj.users_count
        if count > 0:
            url = reverse('admin:authentication_userrole_changelist')
            return format_html(
                '<a href="{}?role__id={}">{} users</a>',
                url, obj.id, count
            )
        return count

    users_count.short_description = 'Users'
    users_count.admin_order_field = 'users_count'

    def save_model(self, request, obj, form, change):
        """Set created_by when creating new role."""
        if not change:
            obj.created_by = request.user
        super().save_model(request, obj, form, change)

    actions = ['activate_roles', 'deactivate_roles']

    def activate_roles(self, request, queryset):
        """Activate selected roles."""
        count = queryset.update(is_active=True)
        self.message_user(request, f'{count} roles activated successfully.')

    activate_roles.short_description = "Activate selected roles"

    def deactivate_roles(self, request, queryset):
        """Deactivate selected roles."""
        # Don't allow deactivating system roles
        system_roles = queryset.filter(is_system_role=True)
        if system_roles.exists():
            self.message_user(
                request,
                f'Cannot deactivate system roles: {", ".join(system_roles.values_list("name", flat=True))}',
                level='ERROR'
            )
            queryset = queryset.filter(is_system_role=False)

        count = queryset.update(is_active=False)
        self.message_user(request, f'{count} roles deactivated successfully.')

    deactivate_roles.short_description = "Deactivate selected roles"


@admin.register(UserRole)
class UserRoleAdmin(admin.ModelAdmin):
    """Admin for user role assignments."""

    list_display = (
        'user', 'role', 'scope_type', 'scope_id', 'is_active',
        'assigned_by', 'assigned_at', 'expires_at'
    )

    list_filter = (
        'is_active', 'scope_type', 'assigned_at', 'expires_at', 'role__service_scope'
    )

    search_fields = (
        'user__username', 'user__email', 'role__name', 'role__display_name',
        'scope_id', 'assigned_by__username'
    )

    ordering = ('-assigned_at',)

    readonly_fields = ('assigned_at',)

    fieldsets = (
        (None, {
            'fields': ('user', 'role', 'is_active')
        }),
        ('Scope', {
            'fields': ('scope_type', 'scope_id')
        }),
        ('Assignment Details', {
            'fields': ('assigned_by', 'assigned_at', 'expires_at', 'conditions')
        }),
    )

    def get_queryset(self, request):
        """Optimize queryset with select_related."""
        return super().get_queryset(request).select_related(
            'user', 'role', 'assigned_by'
        )

    def save_model(self, request, obj, form, change):
        """Set assigned_by when creating new assignment."""
        if not change:
            obj.assigned_by = request.user
        super().save_model(request, obj, form, change)

    actions = ['activate_assignments', 'deactivate_assignments']

    def activate_assignments(self, request, queryset):
        """Activate selected role assignments."""
        count = queryset.update(is_active=True)
        self.message_user(request, f'{count} role assignments activated successfully.')

    activate_assignments.short_description = "Activate selected assignments"

    def deactivate_assignments(self, request, queryset):
        """Deactivate selected role assignments."""
        count = queryset.update(is_active=False)
        self.message_user(request, f'{count} role assignments deactivated successfully.')

    deactivate_assignments.short_description = "Deactivate selected assignments"


@admin.register(ExtendedPermission)
class ExtendedPermissionAdmin(admin.ModelAdmin):
    """Admin for extended permissions."""

    list_display = (
        'codename', 'name', 'service_name', 'category',
        'risk_level', 'requires_approval', 'is_system_permission'
    )

    list_filter = (
        'category', 'service_name', 'risk_level', 'requires_approval',
        'is_system_permission', 'created_at'
    )

    search_fields = (
        'codename', 'name', 'description', 'service_name', 'resource_type'
    )

    ordering = ('service_name', 'category', 'name')

    readonly_fields = ('created_at', 'updated_at')

    fieldsets = (
        (None, {
            'fields': ('codename', 'name', 'description')
        }),
        ('Classification', {
            'fields': ('category', 'service_name', 'resource_type')
        }),
        ('Configuration', {
            'fields': ('actions', 'risk_level', 'requires_approval', 'is_system_permission')
        }),
        ('Timestamps', {
            'fields': ('created_at', 'updated_at'),
            'classes': ('collapse',)
        }),
    )

    def has_delete_permission(self, request, obj=None):
        """Prevent deletion of system permissions."""
        if obj and obj.is_system_permission:
            return False
        return super().has_delete_permission(request, obj)


@admin.register(PermissionRequest)
class PermissionRequestAdmin(admin.ModelAdmin):
    """Admin for permission requests."""

    list_display = (
        'id', 'requester', 'target_user', 'role', 'status',
        'scope_type', 'created_at', 'approved_by'
    )

    list_filter = (
        'status', 'scope_type', 'created_at', 'expires_at'
    )

    search_fields = (
        'requester__username', 'target_user__username', 'role__name',
        'justification', 'approval_notes'
    )

    ordering = ('-created_at',)

    readonly_fields = ('id', 'created_at', 'updated_at')

    fieldsets = (
        (None, {
            'fields': ('requester', 'target_user', 'role', 'status')
        }),
        ('Request Details', {
            'fields': ('justification', 'scope_type', 'scope_id', 'expires_at')
        }),
        ('Approval', {
            'fields': ('approved_by', 'approval_notes'),
            'classes': ('collapse',)
        }),
        ('Timestamps', {
            'fields': ('created_at', 'updated_at'),
            'classes': ('collapse',)
        }),
    )

    def get_queryset(self, request):
        """Optimize queryset with select_related."""
        return super().get_queryset(request).select_related(
            'requester', 'target_user', 'role', 'approved_by'
        )

    actions = ['approve_requests', 'reject_requests']

    def approve_requests(self, request, queryset):
        """Approve selected permission requests."""
        pending_requests = queryset.filter(status='pending')
        for req in pending_requests:
            req.approve(request.user, "Approved via admin interface")

        count = pending_requests.count()
        self.message_user(request, f'{count} permission requests approved successfully.')

    approve_requests.short_description = "Approve selected requests"

    def reject_requests(self, request, queryset):
        """Reject selected permission requests."""
        pending_requests = queryset.filter(status='pending')
        for req in pending_requests:
            req.reject(request.user, "Rejected via admin interface")

        count = pending_requests.count()
        self.message_user(request, f'{count} permission requests rejected successfully.')

    reject_requests.short_description = "Reject selected requests"


@admin.register(AccessLog)
class AccessLogAdmin(admin.ModelAdmin):
    """Admin for access logs."""

    list_display = (
        'timestamp', 'user_or_service', 'action', 'resource',
        'service_name', 'access_granted', 'ip_address'
    )

    list_filter = (
        'access_granted', 'service_name', 'action', 'timestamp'
    )

    search_fields = (
        'user__username', 'service_account__name', 'action',
        'resource', 'ip_address', 'denial_reason'
    )

    ordering = ('-timestamp',)

    readonly_fields = (
        'user', 'service_account', 'action', 'resource', 'service_name',
        'permission_required', 'access_granted', 'denial_reason',
        'ip_address', 'user_agent', 'additional_context', 'timestamp'
    )

    fieldsets = (
        ('Access Information', {
            'fields': ('user', 'service_account', 'action', 'resource', 'service_name')
        }),
        ('Permission Details', {
            'fields': ('permission_required', 'access_granted', 'denial_reason')
        }),
        ('Request Information', {
            'fields': ('ip_address', 'user_agent', 'additional_context')
        }),
        ('Timestamp', {
            'fields': ('timestamp',)
        }),
    )

    def get_queryset(self, request):
        """Optimize queryset with select_related."""
        return super().get_queryset(request).select_related(
            'user', 'service_account'
        )

    def user_or_service(self, obj):
        """Show user or service account."""
        if obj.user:
            return format_html(
                '<span title="User">👤 {}</span>',
                obj.user.username
            )
        elif obj.service_account:
            return format_html(
                '<span title="Service">🔧 {}</span>',
                obj.service_account.name
            )
        return "Anonymous"

    user_or_service.short_description = 'Actor'

    def has_add_permission(self, request):
        """Disable adding access logs through admin."""
        return False

    def has_change_permission(self, request, obj=None):
        """Disable changing access logs through admin."""
        return False

    def has_delete_permission(self, request, obj=None):
        """Only allow superusers to delete access logs."""
        return request.user.is_superuser


# Register Django's built-in Permission model with custom admin
class PermissionAdmin(admin.ModelAdmin):
    """Enhanced admin for Django permissions."""

    list_display = ('name', 'content_type', 'codename')
    list_filter = ('content_type__app_label',)
    search_fields = ('name', 'codename', 'content_type__model')
    ordering = ('content_type__app_label', 'content_type__model', 'name')


# Unregister the default Permission admin and register our enhanced one
# admin.site.unregister(Permission)
admin.site.register(Permission, PermissionAdmin)