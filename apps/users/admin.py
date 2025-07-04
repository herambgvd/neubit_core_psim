"""
Django admin configuration for User Management.

This module provides comprehensive admin interfaces for user management
including users, profiles, sessions, and service accounts.
"""

from django.contrib import admin
from django.contrib.auth.admin import UserAdmin as BaseUserAdmin
from django.contrib.auth import get_user_model
from django.utils.html import format_html
from django.urls import reverse
from django.utils.safestring import mark_safe

from apps.users.models import UserProfile, UserSession, ServiceAccount

User = get_user_model()


class UserProfileInline(admin.StackedInline):
    """Inline admin for user profile."""
    model = UserProfile
    can_delete = False
    verbose_name_plural = 'Profile'
    fk_name = 'user'

    fieldsets = (
        ('Personal Information', {
            'fields': ('avatar', 'bio', 'date_of_birth', 'address')
        }),
        ('Emergency Contact', {
            'fields': ('emergency_contact_name', 'emergency_contact_phone')
        }),
        ('Work Information', {
            'fields': ('hire_date', 'office_location')
        }),
        ('Preferences', {
            'fields': ('notification_preferences', 'ui_preferences'),
            'classes': ('collapse',)
        }),
    )


@admin.register(User)
class UserAdmin(BaseUserAdmin):
    """Enhanced user admin with profile and additional fields."""

    inlines = (UserProfileInline,)

    # List display
    list_display = (
        'username', 'email', 'get_full_name', 'department', 'job_title',
        'is_active', 'is_staff', 'is_account_locked', 'last_login', 'created_at'
    )

    # List filters
    list_filter = (
        'is_active', 'is_staff', 'is_superuser', 'is_service_account',
        'force_password_change', 'department', 'created_at', 'last_login'
    )

    # Search fields
    search_fields = (
        'username', 'first_name', 'last_name', 'email',
        'employee_id', 'department', 'job_title'
    )

    # Ordering
    ordering = ('username',)

    # Read-only fields
    readonly_fields = (
        'uuid', 'password_changed_at', 'last_login_ip', 'failed_login_attempts',
        'account_locked_until', 'password_age_days', 'created_at', 'updated_at'
    )

    # Fieldsets
    fieldsets = (
        (None, {
            'fields': ('username', 'password', 'uuid')
        }),
        ('Personal Info', {
            'fields': ('first_name', 'last_name', 'email', 'employee_id', 'phone_number')
        }),
        ('Work Information', {
            'fields': ('department', 'job_title', 'manager')
        }),
        ('Permissions', {
            'fields': (
                'is_active', 'is_staff', 'is_superuser', 'is_service_account',
                'groups', 'user_permissions'
            ),
        }),
        ('Account Security', {
            'fields': (
                'force_password_change', 'password_changed_at', 'last_login_ip',
                'failed_login_attempts', 'account_locked_until'
            ),
            'classes': ('collapse',)
        }),
        ('Preferences', {
            'fields': ('timezone', 'language'),
        }),
        ('Important Dates', {
            'fields': ('last_login', 'created_at', 'updated_at'),
            'classes': ('collapse',)
        }),
        ('Audit Information', {
            'fields': ('created_by',),
            'classes': ('collapse',)
        }),
    )

    # Add fieldsets
    add_fieldsets = (
        (None, {
            'classes': ('wide',),
            'fields': ('username', 'email', 'password1', 'password2'),
        }),
        ('Personal Information', {
            'fields': ('first_name', 'last_name', 'employee_id', 'phone_number')
        }),
        ('Work Information', {
            'fields': ('department', 'job_title', 'manager')
        }),
        ('Permissions', {
            'fields': ('is_active', 'is_staff', 'is_superuser')
        }),
    )

    # Actions
    actions = ['activate_users', 'deactivate_users', 'unlock_accounts', 'force_password_change']

    def get_full_name(self, obj):
        """Get user's full name or username."""
        return obj.get_full_name() or obj.username

    get_full_name.short_description = 'Full Name'

    def is_account_locked(self, obj):
        """Check if account is locked."""
        locked = obj.is_account_locked
        if locked:
            return format_html(
                '<span style="color: red;">🔒 Locked</span>'
            )
        return format_html('<span style="color: green;">🔓 Unlocked</span>')

    is_account_locked.short_description = 'Account Status'
    is_account_locked.boolean = False

    def password_age_days(self, obj):
        """Get password age in days."""
        age = obj.password_age_days
        if age is None:
            return "Unknown"
        elif age > 90:
            return format_html('<span style="color: red;">{} days</span>', age)
        elif age > 60:
            return format_html('<span style="color: orange;">{} days</span>', age)
        return f"{age} days"

    password_age_days.short_description = 'Password Age'

    # Custom actions
    def activate_users(self, request, queryset):
        """Activate selected users."""
        count = queryset.update(is_active=True)
        self.message_user(request, f'{count} users activated successfully.')

    activate_users.short_description = "Activate selected users"

    def deactivate_users(self, request, queryset):
        """Deactivate selected users."""
        count = queryset.update(is_active=False)
        self.message_user(request, f'{count} users deactivated successfully.')

    deactivate_users.short_description = "Deactivate selected users"

    def unlock_accounts(self, request, queryset):
        """Unlock selected user accounts."""
        for user in queryset:
            user.unlock_account()
        self.message_user(request, f'{queryset.count()} accounts unlocked successfully.')

    unlock_accounts.short_description = "Unlock selected accounts"

    def force_password_change(self, request, queryset):
        """Force password change for selected users."""
        count = queryset.update(force_password_change=True)
        self.message_user(request, f'{count} users will be required to change password on next login.')

    force_password_change.short_description = "Force password change on next login"


@admin.register(UserSession)
class UserSessionAdmin(admin.ModelAdmin):
    """Admin for user sessions."""

    list_display = (
        'user', 'session_key_short', 'ip_address', 'is_active',
        'last_activity', 'expires_at', 'created_at'
    )

    list_filter = (
        'is_active', 'created_at', 'expires_at', 'last_activity'
    )

    search_fields = (
        'user__username', 'user__email', 'session_key', 'ip_address'
    )

    readonly_fields = (
        'session_key', 'device_info', 'location_info', 'created_at', 'last_activity'
    )

    ordering = ('-last_activity',)

    fieldsets = (
        (None, {
            'fields': ('user', 'session_key', 'is_active')
        }),
        ('Session Details', {
            'fields': ('ip_address', 'device_info', 'location_info')
        }),
        ('Timestamps', {
            'fields': ('created_at', 'last_activity', 'expires_at'),
            'classes': ('collapse',)
        }),
    )

    def session_key_short(self, obj):
        """Show shortened session key."""
        return f"{obj.session_key[:8]}..."

    session_key_short.short_description = 'Session Key'

    def has_add_permission(self, request):
        """Disable adding sessions through admin."""
        return False

    actions = ['terminate_sessions']

    def terminate_sessions(self, request, queryset):
        """Terminate selected sessions."""
        for session in queryset:
            session.terminate()
        self.message_user(request, f'{queryset.count()} sessions terminated successfully.')

    terminate_sessions.short_description = "Terminate selected sessions"


@admin.register(ServiceAccount)
class ServiceAccountAdmin(admin.ModelAdmin):
    """Admin for service accounts."""

    list_display = (
        'name', 'service_name', 'is_active', 'api_key_short',
        'expires_at', 'last_used', 'created_by', 'created_at'
    )

    list_filter = (
        'is_active', 'service_name', 'created_at', 'expires_at', 'last_used'
    )

    search_fields = (
        'name', 'service_name', 'description', 'created_by__username'
    )

    readonly_fields = (
        'api_key', 'last_used', 'created_at', 'updated_at'
    )

    ordering = ('-created_at',)

    fieldsets = (
        (None, {
            'fields': ('name', 'service_name', 'description', 'is_active')
        }),
        ('Authentication', {
            'fields': ('api_key',)
        }),
        ('Configuration', {
            'fields': ('allowed_ips', 'scopes', 'expires_at')
        }),
        ('Usage Information', {
            'fields': ('last_used',),
            'classes': ('collapse',)
        }),
        ('Audit Information', {
            'fields': ('created_by', 'created_at', 'updated_at'),
            'classes': ('collapse',)
        }),
    )

    def api_key_short(self, obj):
        """Show shortened API key."""
        api_key_str = str(obj.api_key)
        return f"{api_key_str[:8]}...{api_key_str[-8:]}"

    api_key_short.short_description = 'API Key'

    def save_model(self, request, obj, form, change):
        """Set created_by when creating new service account."""
        if not change:  # Creating new object
            obj.created_by = request.user
        super().save_model(request, obj, form, change)

    actions = ['activate_accounts', 'deactivate_accounts']

    def activate_accounts(self, request, queryset):
        """Activate selected service accounts."""
        count = queryset.update(is_active=True)
        self.message_user(request, f'{count} service accounts activated successfully.')

    activate_accounts.short_description = "Activate selected service accounts"

    def deactivate_accounts(self, request, queryset):
        """Deactivate selected service accounts."""
        count = queryset.update(is_active=False)
        self.message_user(request, f'{count} service accounts deactivated successfully.')

    deactivate_accounts.short_description = "Deactivate selected service accounts"


# Unregister the default User admin and register our custom one
admin.site.unregister(User)
admin.site.register(User, UserAdmin)