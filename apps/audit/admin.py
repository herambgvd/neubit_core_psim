"""
Django admin configuration for Audit & Logging.

This module provides admin interfaces for audit logs, system events,
and compliance reporting.
"""

from django.contrib import admin
from django.utils.html import format_html
from django.utils.safestring import mark_safe
from django.db.models import Count
from django.urls import reverse

# Note: These models will be implemented in Phase 4
# For now, we're creating placeholder admin classes that can be uncommented
# when the actual models are created.

"""
Placeholder admin classes for Audit models.
Uncomment and modify these when implementing Phase 4 Audit & Logging.

from apps.audit.models import (
    AuditLog, SystemEvent, SecurityEvent, ComplianceReport, AuditTrail
)


@admin.register(AuditLog)
class AuditLogAdmin(admin.ModelAdmin):
    list_display = (
        'timestamp', 'user_or_service', 'action', 'object_type',
        'object_id', 'result', 'ip_address'
    )

    list_filter = (
        'action', 'object_type', 'result', 'timestamp', 'user__is_staff'
    )

    search_fields = (
        'user__username', 'service_account__name', 'action',
        'object_type', 'object_repr', 'ip_address'
    )

    ordering = ('-timestamp',)

    readonly_fields = (
        'user', 'service_account', 'action', 'object_type', 'object_id',
        'object_repr', 'changes', 'result', 'ip_address', 'user_agent',
        'session_key', 'correlation_id', 'timestamp'
    )

    fieldsets = (
        ('Actor Information', {
            'fields': ('user', 'service_account', 'ip_address', 'user_agent', 'session_key')
        }),
        ('Action Details', {
            'fields': ('action', 'object_type', 'object_id', 'object_repr', 'result')
        }),
        ('Changes', {
            'fields': ('changes',),
            'classes': ('collapse',)
        }),
        ('Metadata', {
            'fields': ('correlation_id', 'additional_context'),
            'classes': ('collapse',)
        }),
        ('Timestamp', {
            'fields': ('timestamp',)
        }),
    )

    def get_queryset(self, request):
        return super().get_queryset(request).select_related(
            'user', 'service_account'
        )

    def user_or_service(self, obj):
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
        return "System"
    user_or_service.short_description = 'Actor'

    def has_add_permission(self, request):
        return False

    def has_change_permission(self, request, obj=None):
        return False

    def has_delete_permission(self, request, obj=None):
        return request.user.is_superuser


@admin.register(SystemEvent)
class SystemEventAdmin(admin.ModelAdmin):
    list_display = (
        'timestamp', 'event_type', 'severity', 'source_service',
        'message_short', 'is_resolved'
    )

    list_filter = (
        'event_type', 'severity', 'source_service', 'is_resolved', 'timestamp'
    )

    search_fields = (
        'message', 'source_service', 'event_data'
    )

    ordering = ('-timestamp',)

    readonly_fields = ('timestamp', 'correlation_id')

    fieldsets = (
        (None, {
            'fields': ('event_type', 'severity', 'source_service', 'is_resolved')
        }),
        ('Event Details', {
            'fields': ('message', 'event_data')
        }),
        ('Resolution', {
            'fields': ('resolution_notes', 'resolved_by', 'resolved_at'),
            'classes': ('collapse',)
        }),
        ('Metadata', {
            'fields': ('correlation_id', 'timestamp'),
            'classes': ('collapse',)
        }),
    )

    def message_short(self, obj):
        return obj.message[:50] + "..." if len(obj.message) > 50 else obj.message
    message_short.short_description = 'Message'

    actions = ['mark_resolved', 'mark_unresolved']

    def mark_resolved(self, request, queryset):
        count = queryset.update(is_resolved=True, resolved_by=request.user)
        self.message_user(request, f'{count} events marked as resolved.')
    mark_resolved.short_description = "Mark selected events as resolved"

    def mark_unresolved(self, request, queryset):
        count = queryset.update(is_resolved=False, resolved_by=None, resolved_at=None)
        self.message_user(request, f'{count} events marked as unresolved.')
    mark_unresolved.short_description = "Mark selected events as unresolved"


@admin.register(SecurityEvent)
class SecurityEventAdmin(admin.ModelAdmin):
    list_display = (
        'timestamp', 'event_type', 'severity', 'user_or_ip',
        'threat_level', 'is_false_positive', 'is_resolved'
    )

    list_filter = (
        'event_type', 'severity', 'threat_level', 'is_false_positive',
        'is_resolved', 'timestamp'
    )

    search_fields = (
        'user__username', 'ip_address', 'user_agent', 'description'
    )

    ordering = ('-timestamp',)

    readonly_fields = ('timestamp', 'detection_rule', 'correlation_id')

    fieldsets = (
        ('Event Information', {
            'fields': ('event_type', 'severity', 'threat_level', 'description')
        }),
        ('Source Information', {
            'fields': ('user', 'ip_address', 'user_agent', 'source_service')
        }),
        ('Detection', {
            'fields': ('detection_rule', 'indicators', 'risk_score')
        }),
        ('Response', {
            'fields': ('is_false_positive', 'is_resolved', 'response_actions')
        }),
        ('Resolution', {
            'fields': ('resolution_notes', 'resolved_by', 'resolved_at'),
            'classes': ('collapse',)
        }),
        ('Metadata', {
            'fields': ('correlation_id', 'additional_data', 'timestamp'),
            'classes': ('collapse',)
        }),
    )

    def get_queryset(self, request):
        return super().get_queryset(request).select_related('user', 'resolved_by')

    def user_or_ip(self, obj):
        if obj.user:
            return format_html(
                '<span title="User">👤 {}</span>',
                obj.user.username
            )
        return format_html(
            '<span title="IP Address">🌐 {}</span>',
            obj.ip_address
        )
    user_or_ip.short_description = 'Source'

    actions = ['mark_false_positive', 'mark_resolved', 'escalate_threat']

    def mark_false_positive(self, request, queryset):
        count = queryset.update(is_false_positive=True, resolved_by=request.user)
        self.message_user(request, f'{count} events marked as false positives.')
    mark_false_positive.short_description = "Mark as false positive"

    def mark_resolved(self, request, queryset):
        count = queryset.update(is_resolved=True, resolved_by=request.user)
        self.message_user(request, f'{count} security events resolved.')
    mark_resolved.short_description = "Mark as resolved"

    def escalate_threat(self, request, queryset):
        count = queryset.update(threat_level='high')
        self.message_user(request, f'{count} events escalated to high threat level.')
    escalate_threat.short_description = "Escalate threat level"


@admin.register(ComplianceReport)
class ComplianceReportAdmin(admin.ModelAdmin):
    list_display = (
        'name', 'compliance_framework', 'report_type', 'status',
        'generated_by', 'generated_at', 'file_size'
    )

    list_filter = (
        'compliance_framework', 'report_type', 'status', 'generated_at'
    )

    search_fields = (
        'name', 'description', 'compliance_framework', 'generated_by__username'
    )

    ordering = ('-generated_at',)

    readonly_fields = ('generated_at', 'file_size_display', 'report_hash')

    fieldsets = (
        (None, {
            'fields': ('name', 'compliance_framework', 'report_type', 'status')
        }),
        ('Report Details', {
            'fields': ('description', 'date_from', 'date_to', 'filters')
        }),
        ('Generation', {
            'fields': ('generated_by', 'generated_at', 'generation_duration')
        }),
        ('File Information', {
            'fields': ('report_file', 'file_size_display', 'report_hash'),
            'classes': ('collapse',)
        }),
        ('Metadata', {
            'fields': ('metadata',),
            'classes': ('collapse',)
        }),
    )

    def get_queryset(self, request):
        return super().get_queryset(request).select_related('generated_by')

    def file_size(self, obj):
        if obj.report_file:
            size = obj.report_file.size
            if size < 1024:
                return f"{size} B"
            elif size < 1024 * 1024:
                return f"{size / 1024:.1f} KB"
            else:
                return f"{size / (1024 * 1024):.1f} MB"
        return "No file"
    file_size.short_description = 'File Size'

    def file_size_display(self, obj):
        return self.file_size(obj)
    file_size_display.short_description = 'File Size'


@admin.register(AuditTrail)
class AuditTrailAdmin(admin.ModelAdmin):
    list_display = (
        'timestamp', 'trail_type', 'object_type', 'object_id',
        'action', 'user_or_service', 'changes_count'
    )

    list_filter = (
        'trail_type', 'action', 'object_type', 'timestamp'
    )

    search_fields = (
        'object_id', 'object_repr', 'user__username', 'service_account__name'
    )

    ordering = ('-timestamp',)

    readonly_fields = (
        'trail_type', 'object_type', 'object_id', 'object_repr',
        'action', 'user', 'service_account', 'changes', 'metadata',
        'correlation_id', 'timestamp'
    )

    fieldsets = (
        ('Trail Information', {
            'fields': ('trail_type', 'action', 'timestamp')
        }),
        ('Object Information', {
            'fields': ('object_type', 'object_id', 'object_repr')
        }),
        ('Actor Information', {
            'fields': ('user', 'service_account')
        }),
        ('Changes', {
            'fields': ('changes',)
        }),
        ('Metadata', {
            'fields': ('metadata', 'correlation_id'),
            'classes': ('collapse',)
        }),
    )

    def get_queryset(self, request):
        return super().get_queryset(request).select_related(
            'user', 'service_account'
        )

    def user_or_service(self, obj):
        if obj.user:
            return obj.user.username
        elif obj.service_account:
            return f"Service: {obj.service_account.name}"
        return "System"
    user_or_service.short_description = 'Actor'

    def changes_count(self, obj):
        if obj.changes:
            return len(obj.changes)
        return 0
    changes_count.short_description = 'Changes'

    def has_add_permission(self, request):
        return False

    def has_change_permission(self, request, obj=None):
        return False

    def has_delete_permission(self, request, obj=None):
        return request.user.is_superuser
"""


# Placeholder admin registration
# These will be uncommented when the actual models are implemented in Phase 4

# Example of how to register when models are ready:
# admin.site.register(AuditLog, AuditLogAdmin)
# admin.site.register(SystemEvent, SystemEventAdmin)
# admin.site.register(SecurityEvent, SecurityEventAdmin)
# admin.site.register(ComplianceReport, ComplianceReportAdmin)
# admin.site.register(AuditTrail, AuditTrailAdmin)

# For now, we'll create a simple placeholder
class AuditPlaceholderAdmin(admin.ModelAdmin):
    """
    Placeholder admin for audit logs.
    This will be replaced with actual audit models in Phase 4.
    """

    def has_module_permission(self, request):
        """Hide this from admin until Phase 4 is implemented."""
        return False


# Temporary placeholder message
def add_audit_admin_message():
    """Add a message about audit management coming in Phase 4."""
    pass  # This will be implemented when we add audit models