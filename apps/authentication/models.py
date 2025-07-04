"""
RBAC (Role-Based Access Control) models for Core Platform.

This module implements a comprehensive RBAC system with:
- Hierarchical roles
- Fine-grained permissions
- Service-specific permissions
- Context-aware access control
- Audit trails
"""

import uuid

import structlog
from django.contrib.auth.models import Permission as DjangoPermission
from django.core.exceptions import ValidationError
from django.db import models
from django.utils import timezone

# Configure structured logger
logger = structlog.get_logger(__name__)


class Role(models.Model):
    name = models.CharField(max_length=100, unique=True)
    display_name = models.CharField(max_length=150)
    description = models.TextField(blank=True)
    parent_role = models.ForeignKey('self', on_delete=models.CASCADE, null=True, blank=True, related_name='child_roles')
    service_scope = models.CharField(max_length=100, blank=True)
    is_system_role = models.BooleanField(default=False)
    is_active = models.BooleanField(default=True)
    priority = models.PositiveIntegerField(default=0)
    permissions = models.ManyToManyField(DjangoPermission, through='RolePermission', blank=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    created_by = models.ForeignKey('users.User', on_delete=models.SET_NULL, null=True, blank=True,
                                   related_name='created_roles')

    class Meta:
        db_table = 'auth_role'
        ordering = ['-priority', 'name']
        indexes = [
            models.Index(fields=['name']),
            models.Index(fields=['service_scope']),
            models.Index(fields=['is_active']),
            models.Index(fields=['priority']),
        ]

    def __str__(self):
        return f"{self.display_name} ({self.service_scope})" if self.service_scope else self.display_name

    def clean(self):
        super().clean()
        if self.parent_role:
            current = self.parent_role
            while current:
                if current == self:
                    raise ValidationError("Role hierarchy cannot be circular")
                current = current.parent_role

    def save(self, *args, **kwargs):
        self.clean()
        super().save(*args, **kwargs)

    def get_all_permissions(self):
        permission_ids = set(self.permissions.values_list('id', flat=True))
        current = self.parent_role
        while current:
            permission_ids.update(current.permissions.values_list('id', flat=True))
            current = current.parent_role
        return DjangoPermission.objects.filter(id__in=permission_ids)

    def get_hierarchy_path(self):
        path = []
        current = self
        while current:
            path.insert(0, current.name)
            current = current.parent_role
        return path

    def has_permission(self, permission_codename, service_name=None):
        permissions = self.get_all_permissions()
        query = {'codename': permission_codename}
        if service_name:
            query['content_type__app_label'] = service_name
        return permissions.filter(**query).exists()

    def get_child_roles_recursive(self):
        child_roles = set()

        def collect(role):
            for child in role.child_roles.all():
                child_roles.add(child)
                collect(child)

        collect(self)
        return child_roles


class RolePermission(models.Model):
    role = models.ForeignKey(Role, on_delete=models.CASCADE)
    permission = models.ForeignKey(DjangoPermission, on_delete=models.CASCADE)
    granted_by = models.ForeignKey('users.User', on_delete=models.SET_NULL, null=True, blank=True)
    granted_at = models.DateTimeField(auto_now_add=True)
    conditions = models.JSONField(default=dict, blank=True)
    expires_at = models.DateTimeField(null=True, blank=True)

    class Meta:
        db_table = 'auth_role_permission'
        unique_together = ['role', 'permission']

    def __str__(self):
        return f"{self.role.name} -> {self.permission.codename}"

    @property
    def is_expired(self):
        return self.expires_at and timezone.now() > self.expires_at


class UserRole(models.Model):
    user = models.ForeignKey('users.User', on_delete=models.CASCADE, related_name='user_roles')
    role = models.ForeignKey(Role, on_delete=models.CASCADE, related_name='user_assignments')
    scope_type = models.CharField(max_length=50, choices=[
        ('global', 'Global'),
        ('location', 'Location'),
        ('department', 'Department'),
        ('project', 'Project')
    ], default='global')
    scope_id = models.CharField(max_length=100, blank=True)
    assigned_by = models.ForeignKey('users.User', on_delete=models.SET_NULL, null=True, blank=True,
                                    related_name='assigned_roles')
    assigned_at = models.DateTimeField(auto_now_add=True)
    expires_at = models.DateTimeField(null=True, blank=True)
    is_active = models.BooleanField(default=True)
    conditions = models.JSONField(default=dict, blank=True)

    class Meta:
        db_table = 'auth_user_role'
        unique_together = ['user', 'role', 'scope_type', 'scope_id']
        ordering = ['-assigned_at']
        indexes = [
            models.Index(fields=['user', 'is_active']),
            models.Index(fields=['role']),
            models.Index(fields=['scope_type', 'scope_id']),
            models.Index(fields=['expires_at']),
        ]

    def __str__(self):
        return f"{self.user.username} -> {self.role.name}"

    @property
    def is_expired(self):
        return self.expires_at and timezone.now() > self.expires_at

    def is_valid_for_context(self, scope_type=None, scope_id=None):
        if not self.is_active or self.is_expired:
            return False
        if self.scope_type == 'global':
            return True
        return self.scope_type == scope_type and self.scope_id == scope_id


class ExtendedPermission(models.Model):
    codename = models.CharField(max_length=100)
    name = models.CharField(max_length=255)
    description = models.TextField(blank=True)
    category = models.CharField(max_length=50, choices=[
        ('user_management', 'User Management'),
        ('location_management', 'Location Management'),
        ('device_control', 'Device Control'),
        ('video_access', 'Video Access'),
        ('access_control', 'Access Control'),
        ('reporting', 'Reporting'),
        ('system_admin', 'System Administration'),
        ('audit', 'Audit')
    ])
    service_name = models.CharField(max_length=100)
    resource_type = models.CharField(max_length=100, blank=True)
    actions = models.JSONField(default=list)
    is_system_permission = models.BooleanField(default=False)
    risk_level = models.CharField(max_length=20, choices=[
        ('low', 'Low'),
        ('medium', 'Medium'),
        ('high', 'High'),
        ('critical', 'Critical')
    ], default='low')
    requires_approval = models.BooleanField(default=False)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        db_table = 'auth_permission_extended'
        unique_together = ['codename', 'service_name']
        ordering = ['service_name', 'category', 'name']

    def __str__(self):
        return f"{self.service_name}.{self.codename}"


class PermissionRequest(models.Model):
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    requester = models.ForeignKey('users.User', on_delete=models.CASCADE, related_name='permission_requests')
    target_user = models.ForeignKey('users.User', on_delete=models.CASCADE, related_name='permission_requests_for')
    role = models.ForeignKey(Role, on_delete=models.CASCADE)
    justification = models.TextField()
    scope_type = models.CharField(max_length=50, choices=[
        ('global', 'Global'),
        ('location', 'Location'),
        ('department', 'Department'),
        ('project', 'Project')
    ], default='global')
    scope_id = models.CharField(max_length=100, blank=True)
    status = models.CharField(max_length=20, choices=[
        ('pending', 'Pending'),
        ('approved', 'Approved'),
        ('rejected', 'Rejected'),
        ('expired', 'Expired')
    ], default='pending')
    approved_by = models.ForeignKey('users.User', on_delete=models.SET_NULL, null=True, blank=True,
                                    related_name='approved_permission_requests')
    approval_notes = models.TextField(blank=True)
    expires_at = models.DateTimeField(null=True, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        db_table = 'auth_permission_request'
        ordering = ['-created_at']

    def __str__(self):
        return f"Request: {self.role.name} for {self.target_user.username}"

    def approve(self, approver, notes=""):
        self.status = 'approved'
        self.approved_by = approver
        self.approval_notes = notes
        self.save()
        UserRole.objects.create(
            user=self.target_user,
            role=self.role,
            scope_type=self.scope_type,
            scope_id=self.scope_id,
            assigned_by=approver
        )
        logger.info("permission_request_approved", request_id=str(self.id),
                    requester=self.requester.username, target_user=self.target_user.username,
                    role=self.role.name, approver=approver.username)

    def reject(self, approver, notes=""):
        self.status = 'rejected'
        self.approved_by = approver
        self.approval_notes = notes
        self.save()
        logger.info("permission_request_rejected", request_id=str(self.id),
                    requester=self.requester.username, target_user=self.target_user.username,
                    role=self.role.name, approver=approver.username)


class AccessLog(models.Model):
    user = models.ForeignKey('users.User', on_delete=models.SET_NULL, null=True, blank=True)
    service_account = models.ForeignKey('users.ServiceAccount', on_delete=models.SET_NULL, null=True, blank=True)
    action = models.CharField(max_length=100)
    resource = models.CharField(max_length=255)
    service_name = models.CharField(max_length=100)
    permission_required = models.CharField(max_length=100)
    access_granted = models.BooleanField()
    denial_reason = models.CharField(max_length=255, blank=True)
    ip_address = models.GenericIPAddressField()
    user_agent = models.TextField(blank=True)
    additional_context = models.JSONField(default=dict, blank=True)
    timestamp = models.DateTimeField(auto_now_add=True)

    class Meta:
        db_table = 'auth_access_log'
        ordering = ['-timestamp']
        indexes = [
            models.Index(fields=['user', 'timestamp']),
            models.Index(fields=['service_name', 'timestamp']),
            models.Index(fields=['access_granted', 'timestamp']),
            models.Index(fields=['ip_address']),
        ]

    def __str__(self):
        actor = self.user.username if self.user else (
            self.service_account.name if self.service_account else "Anonymous")
        return f"{'✓' if self.access_granted else '✗'} {actor} -> {self.action} on {self.resource}"
