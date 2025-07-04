"""
User models for Neubit PSIM Core Platform Service.

This module contains the custom user model and related models for
comprehensive user management in the microservices ecosystem.
"""

import uuid

import structlog
from django.contrib.auth.models import AbstractUser, Permission
from django.contrib.contenttypes.models import ContentType
from django.core.validators import RegexValidator
from django.db import models
from django.utils import timezone

# Configure structured logger
logger = structlog.get_logger(__name__)


class User(AbstractUser):
    """
    Custom User model for Core Platform.

    Extends Django's AbstractUser to add PSIM-specific fields
    and functionality for microservice authentication.
    """

    # UUID for external API references
    uuid = models.UUIDField(default=uuid.uuid4, editable=False, unique=True,
                            help_text="Unique identifier for API references")
    # Enhanced user information
    employee_id = models.CharField(max_length=50, blank=True, null=True, unique=True,
                                   help_text="Employee ID from HR system")
    phone_number = models.CharField(max_length=20, blank=True,
                                    validators=[RegexValidator(
                                        regex=r'^\+?1?\d{9,15}$',
                                        message="Phone number must be entered in the format: '+999999999'. Up to 15 digits allowed."
                                    )
                                    ],
                                    help_text="Contact phone number"
                                    )
    department = models.CharField(max_length=100, blank=True, help_text="Department or division")
    job_title = models.CharField(max_length=100, blank=True, help_text="Job title or position")
    manager = models.ForeignKey('self', on_delete=models.SET_NULL, null=True, blank=True, related_name='subordinates',
                                help_text="Direct manager")
    # Account status and metadata
    is_service_account = models.BooleanField(default=False,
                                             help_text="Whether this is a service account for API access")
    force_password_change = models.BooleanField(default=False, help_text="User must change password on next login")
    password_changed_at = models.DateTimeField(null=True, blank=True, help_text="When password was last changed")
    last_login_ip = models.GenericIPAddressField(null=True, blank=True, help_text="IP address of last login")
    failed_login_attempts = models.PositiveIntegerField(default=0,
                                                        help_text="Number of consecutive failed login attempts")
    account_locked_until = models.DateTimeField(null=True, blank=True, help_text="Account locked until this timestamp")
    # Preferences and settings
    timezone = models.CharField(max_length=50, default='Asia/Kolkata', help_text="User's timezone preference")
    language = models.CharField(max_length=10, default='en',
                                choices=[
                                    ('en', 'English'),
                                    ('hi', 'Hindi'),
                                    ('es', 'Spanish'),
                                    ('fr', 'French'),
                                ],
                                help_text="Preferred language"
                                )
    # Audit fields
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    created_by = models.ForeignKey(
        'self',
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name='created_users',
        help_text="User who created this account"
    )

    class Meta:
        db_table = 'users_user'
        verbose_name = 'User'
        verbose_name_plural = 'Users'
        ordering = ['username']
        indexes = [
            models.Index(fields=['uuid']),
            models.Index(fields=['employee_id']),
            models.Index(fields=['email']),
            models.Index(fields=['is_active', 'is_staff']),
            models.Index(fields=['created_at']),
        ]

    def __str__(self):
        return f"{self.get_full_name() or self.username} ({self.email})"

    def save(self, *args, **kwargs):
        """Override save to update password_changed_at when password changes."""
        if self.pk:
            old_user = User.objects.get(pk=self.pk)
            if old_user.password != self.password:
                self.password_changed_at = timezone.now()
        else:
            # New user
            self.password_changed_at = timezone.now()

        super().save(*args, **kwargs)

    @property
    def full_name(self):
        """Get user's full name."""
        return self.get_full_name() or self.username

    @property
    def is_account_locked(self):
        """Check if account is currently locked."""
        if self.account_locked_until:
            return timezone.now() < self.account_locked_until
        return False

    @property
    def password_age_days(self):
        """Get age of current password in days."""
        if self.password_changed_at:
            return (timezone.now() - self.password_changed_at).days
        return None

    def lock_account(self, duration_minutes=30):
        """
        Lock user account for specified duration.

        Args:
            duration_minutes: How long to lock account (default: 30 minutes)
        """
        from datetime import timedelta
        self.account_locked_until = timezone.now() + timedelta(minutes=duration_minutes)
        self.save(update_fields=['account_locked_until'])

        logger.warning(
            "user_account_locked",
            user_id=self.id,
            username=self.username,
            duration_minutes=duration_minutes
        )

    def unlock_account(self):
        """Unlock user account and reset failed attempts."""
        self.account_locked_until = None
        self.failed_login_attempts = 0
        self.save(update_fields=['account_locked_until', 'failed_login_attempts'])

        logger.info(
            "user_account_unlocked",
            user_id=self.id,
            username=self.username
        )

    def record_failed_login(self):
        """Record a failed login attempt."""
        self.failed_login_attempts += 1

        # Lock account after 5 failed attempts
        if self.failed_login_attempts >= 5:
            self.lock_account(30)  # Lock for 30 minutes

        self.save(update_fields=['failed_login_attempts'])

    def record_successful_login(self, ip_address=None):
        """
        Record a successful login.

        Args:
            ip_address: IP address of login
        """
        self.failed_login_attempts = 0
        self.last_login = timezone.now()
        if ip_address:
            self.last_login_ip = ip_address

        self.save(update_fields=['failed_login_attempts', 'last_login', 'last_login_ip'])

    def get_permissions_for_service(self, service_name):
        """
        Get all permissions for a specific service.

        Args:
            service_name: Name of the microservice

        Returns:
            QuerySet of permissions for the service
        """
        return self.user_permissions.filter(
            content_type__app_label=service_name
        ).union(
            Permission.objects.filter(
                group__user=self,
                content_type__app_label=service_name
            )
        )

    def has_service_permission(self, service_name, permission_codename):
        """
        Check if user has specific permission for a service.

        Args:
            service_name: Name of the microservice
            permission_codename: Permission code to check

        Returns:
            True if user has permission
        """
        if self.is_superuser:
            return True

        try:
            content_type = ContentType.objects.get(app_label=service_name)
            permission = Permission.objects.get(
                content_type=content_type,
                codename=permission_codename
            )
            return self.has_perm(f"{service_name}.{permission_codename}")
        except (ContentType.DoesNotExist, Permission.DoesNotExist):
            return False


class UserProfile(models.Model):
    """
    Extended user profile information.

    Contains additional user information that's not part of the core
    authentication model.
    """

    user = models.OneToOneField(
        User,
        on_delete=models.CASCADE,
        related_name='profile'
    )

    # Personal information
    avatar = models.ImageField(
        upload_to='avatars/',
        null=True,
        blank=True,
        help_text="User profile picture"
    )

    bio = models.TextField(
        blank=True,
        max_length=500,
        help_text="Short biography or description"
    )

    date_of_birth = models.DateField(
        null=True,
        blank=True,
        help_text="Date of birth"
    )

    # Contact information
    address = models.TextField(
        blank=True,
        help_text="Physical address"
    )

    emergency_contact_name = models.CharField(
        max_length=100,
        blank=True,
        help_text="Emergency contact person"
    )

    emergency_contact_phone = models.CharField(
        max_length=20,
        blank=True,
        help_text="Emergency contact phone number"
    )

    # Work information
    hire_date = models.DateField(
        null=True,
        blank=True,
        help_text="Date of hire"
    )

    office_location = models.CharField(
        max_length=100,
        blank=True,
        help_text="Primary office location"
    )

    work_schedule = models.JSONField(
        default=dict,
        blank=True,
        help_text="Work schedule configuration"
    )

    # Preferences
    notification_preferences = models.JSONField(
        default=dict,
        blank=True,
        help_text="User notification preferences"
    )

    ui_preferences = models.JSONField(
        default=dict,
        blank=True,
        help_text="UI/UX preferences and settings"
    )

    # Audit fields
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        db_table = 'users_profile'
        verbose_name = 'User Profile'
        verbose_name_plural = 'User Profiles'

    def __str__(self):
        return f"Profile for {self.user.username}"

    @property
    def age(self):
        """Calculate user's age from date of birth."""
        if self.date_of_birth:
            today = timezone.now().date()
            return today.year - self.date_of_birth.year - (
                    (today.month, today.day) < (self.date_of_birth.month, self.date_of_birth.day)
            )
        return None


class UserSession(models.Model):
    """
    Track user sessions across multiple devices and services.

    Provides session management for security and audit purposes.
    """

    user = models.ForeignKey(
        User,
        on_delete=models.CASCADE,
        related_name='sessions'
    )

    session_key = models.CharField(
        max_length=40,
        unique=True,
        help_text="Session identifier"
    )

    device_info = models.JSONField(
        default=dict,
        help_text="Device and browser information"
    )

    ip_address = models.GenericIPAddressField(
        help_text="IP address of session"
    )

    location_info = models.JSONField(
        default=dict,
        blank=True,
        help_text="Geographic location information"
    )

    is_active = models.BooleanField(
        default=True,
        help_text="Whether session is currently active"
    )

    last_activity = models.DateTimeField(
        auto_now=True,
        help_text="Last activity timestamp"
    )

    created_at = models.DateTimeField(auto_now_add=True)
    expires_at = models.DateTimeField(
        help_text="Session expiration time"
    )

    class Meta:
        db_table = 'users_session'
        verbose_name = 'User Session'
        verbose_name_plural = 'User Sessions'
        ordering = ['-last_activity']
        indexes = [
            models.Index(fields=['user', 'is_active']),
            models.Index(fields=['session_key']),
            models.Index(fields=['expires_at']),
        ]

    def __str__(self):
        return f"Session for {self.user.username} from {self.ip_address}"

    @property
    def is_expired(self):
        """Check if session has expired."""
        return timezone.now() > self.expires_at

    def terminate(self):
        """Terminate the session."""
        self.is_active = False
        self.save(update_fields=['is_active'])

        logger.info(
            "user_session_terminated",
            user_id=self.user.id,
            session_key=self.session_key,
            ip_address=self.ip_address
        )


class ServiceAccount(models.Model):
    """
    Service accounts for microservice authentication.

    Represents service-to-service authentication accounts
    with specific permissions and scopes.
    """

    name = models.CharField(
        max_length=100,
        unique=True,
        help_text="Service account name"
    )

    description = models.TextField(
        blank=True,
        help_text="Description of service account purpose"
    )

    service_name = models.CharField(
        max_length=100,
        help_text="Name of the microservice"
    )

    api_key = models.UUIDField(
        default=uuid.uuid4,
        unique=True,
        help_text="API key for service authentication"
    )

    allowed_ips = models.JSONField(
        default=list,
        blank=True,
        help_text="Allowed IP addresses for this service account"
    )

    scopes = models.JSONField(
        default=list,
        help_text="Allowed scopes/permissions for this service"
    )

    is_active = models.BooleanField(
        default=True,
        help_text="Whether service account is active"
    )

    expires_at = models.DateTimeField(
        null=True,
        blank=True,
        help_text="Service account expiration time"
    )

    last_used = models.DateTimeField(
        null=True,
        blank=True,
        help_text="Last time this service account was used"
    )

    created_by = models.ForeignKey(
        User,
        on_delete=models.SET_NULL,
        null=True,
        related_name='created_service_accounts',
        help_text="User who created this service account"
    )

    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        db_table = 'users_service_account'
        verbose_name = 'Service Account'
        verbose_name_plural = 'Service Accounts'
        ordering = ['service_name', 'name']

    def __str__(self):
        return f"Service Account: {self.name} ({self.service_name})"

    @property
    def is_expired(self):
        """Check if service account has expired."""
        if self.expires_at:
            return timezone.now() > self.expires_at
        return False

    def record_usage(self, ip_address=None):
        """Record usage of this service account."""
        self.last_used = timezone.now()
        self.save(update_fields=['last_used'])

        logger.info(
            "service_account_used",
            service_account=self.name,
            service_name=self.service_name,
            ip_address=ip_address
        )

    def has_scope(self, scope):
        """
        Check if service account has specific scope.

        Args:
            scope: Scope to check

        Returns:
            True if service account has the scope
        """
        return scope in self.scopes or '*' in self.scopes

    def is_ip_allowed(self, ip_address):
        """
        Check if IP address is allowed for this service account.

        Args:
            ip_address: IP address to check

        Returns:
            True if IP is allowed
        """
        if not self.allowed_ips:
            return True  # No IP restrictions

        return ip_address in self.allowed_ips
