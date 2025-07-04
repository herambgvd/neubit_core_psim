"""
Serializers for authentication and user management APIs.

This module provides DRF serializers for all authentication-related
API endpoints including login, registration, and user management.
"""

import structlog
from django.contrib.auth import get_user_model
from django.contrib.auth.password_validation import validate_password
from django.core.exceptions import ValidationError
from rest_framework import serializers

# Configure structured logger
logger = structlog.get_logger(__name__)

User = get_user_model()


class LoginSerializer(serializers.Serializer):
    """
    Serializer for user login.

    Validates login credentials and optional settings.
    """

    username = serializers.CharField(
        max_length=255,
        help_text="Username or email address"
    )

    password = serializers.CharField(
        max_length=128,
        style={'input_type': 'password'},
        help_text="User password"
    )

    remember_me = serializers.BooleanField(
        default=False,
        required=False,
        help_text="Remember login for extended period"
    )

    def validate_username(self, value):
        """Validate username is not empty."""
        if not value.strip():
            raise serializers.ValidationError("Username cannot be empty")
        return value.strip()

    def validate_password(self, value):
        """Validate password is not empty."""
        if not value:
            raise serializers.ValidationError("Password cannot be empty")
        return value


class TokenRefreshSerializer(serializers.Serializer):
    """
    Serializer for token refresh requests.
    """

    refresh_token = serializers.CharField(
        max_length=500,
        help_text="Refresh token to generate new access token"
    )

    def validate_refresh_token(self, value):
        """Validate refresh token is not empty."""
        if not value.strip():
            raise serializers.ValidationError("Refresh token cannot be empty")
        return value.strip()


class UserRegistrationSerializer(serializers.ModelSerializer):
    """
    Serializer for user registration.

    Handles user creation with validation and profile setup.
    """

    password = serializers.CharField(
        max_length=128,
        style={'input_type': 'password'},
        write_only=True,
        help_text="User password"
    )

    password_confirm = serializers.CharField(
        max_length=128,
        style={'input_type': 'password'},
        write_only=True,
        help_text="Password confirmation"
    )

    class Meta:
        model = User
        fields = [
            'username', 'email', 'first_name', 'last_name',
            'password', 'password_confirm', 'phone_number',
            'department', 'job_title'
        ]
        extra_kwargs = {
            'email': {'required': True},
            'first_name': {'required': True},
            'last_name': {'required': True},
        }

    def validate_username(self, value):
        """Validate username."""
        if User.objects.filter(username=value).exists():
            raise serializers.ValidationError("Username already exists")
        return value

    def validate_email(self, value):
        """Validate email address."""
        if User.objects.filter(email=value).exists():
            raise serializers.ValidationError("Email address already registered")
        return value

    def validate_password(self, value):
        """Validate password strength."""
        try:
            validate_password(value)
        except ValidationError as e:
            raise serializers.ValidationError(list(e.messages))
        return value

    def validate(self, attrs):
        """Validate password confirmation."""
        password = attrs.get('password')
        password_confirm = attrs.get('password_confirm')

        if password != password_confirm:
            raise serializers.ValidationError({
                'password_confirm': 'Passwords do not match'
            })

        return attrs

    def create(self, validated_data):
        """Create new user account."""
        # Remove password_confirm from validated data
        validated_data.pop('password_confirm', None)

        # Extract password
        password = validated_data.pop('password')

        # Create user
        user = User.objects.create_user(
            password=password,
            **validated_data
        )

        logger.info(
            "user_created_via_registration",
            user_id=user.id,
            username=user.username,
            email=user.email
        )

        return user


class UserProfileSerializer(serializers.ModelSerializer):
    """
    Serializer for user profile management.

    Handles user profile information including extended fields.
    """

    # Profile fields
    avatar = serializers.ImageField(
        source='profile.avatar',
        required=False,
        allow_null=True
    )

    bio = serializers.CharField(
        source='profile.bio',
        required=False,
        allow_blank=True,
        max_length=500
    )

    date_of_birth = serializers.DateField(
        source='profile.date_of_birth',
        required=False,
        allow_null=True
    )

    address = serializers.CharField(
        source='profile.address',
        required=False,
        allow_blank=True
    )

    emergency_contact_name = serializers.CharField(
        source='profile.emergency_contact_name',
        required=False,
        allow_blank=True,
        max_length=100
    )

    emergency_contact_phone = serializers.CharField(
        source='profile.emergency_contact_phone',
        required=False,
        allow_blank=True,
        max_length=20
    )

    hire_date = serializers.DateField(
        source='profile.hire_date',
        required=False,
        allow_null=True
    )

    office_location = serializers.CharField(
        source='profile.office_location',
        required=False,
        allow_blank=True,
        max_length=100
    )

    notification_preferences = serializers.JSONField(
        source='profile.notification_preferences',
        required=False,
        default=dict
    )

    ui_preferences = serializers.JSONField(
        source='profile.ui_preferences',
        required=False,
        default=dict
    )

    # Read-only fields
    uuid = serializers.UUIDField(read_only=True)
    last_login = serializers.DateTimeField(read_only=True)
    is_account_locked = serializers.BooleanField(read_only=True)
    password_age_days = serializers.IntegerField(read_only=True)
    created_at = serializers.DateTimeField(read_only=True)
    updated_at = serializers.DateTimeField(read_only=True)

    class Meta:
        model = User
        fields = [
            'id', 'uuid', 'username', 'email', 'first_name', 'last_name',
            'phone_number', 'department', 'job_title', 'timezone', 'language',
            'is_staff', 'is_superuser', 'is_active', 'last_login',
            'is_account_locked', 'password_age_days', 'force_password_change',
            'created_at', 'updated_at',
            # Profile fields
            'avatar', 'bio', 'date_of_birth', 'address',
            'emergency_contact_name', 'emergency_contact_phone',
            'hire_date', 'office_location', 'notification_preferences',
            'ui_preferences'
        ]
        read_only_fields = [
            'id', 'uuid', 'username', 'is_staff', 'is_superuser',
            'is_active', 'last_login', 'is_account_locked',
            'password_age_days', 'force_password_change',
            'created_at', 'updated_at'
        ]

    def validate_email(self, value):
        """Validate email uniqueness (excluding current user)."""
        if self.instance and self.instance.email == value:
            return value

        if User.objects.filter(email=value).exists():
            raise serializers.ValidationError("Email address already in use")
        return value

    def validate_phone_number(self, value):
        """Validate phone number format."""
        if value and not value.startswith('+'):
            # Add basic validation - can be enhanced based on requirements
            if not value.replace('-', '').replace(' ', '').replace('(', '').replace(')', '').isdigit():
                raise serializers.ValidationError("Invalid phone number format")
        return value

    def update(self, instance, validated_data):
        """Update user and profile information."""
        # Extract profile data
        profile_data = {}
        profile_fields = [
            'avatar', 'bio', 'date_of_birth', 'address',
            'emergency_contact_name', 'emergency_contact_phone',
            'hire_date', 'office_location', 'notification_preferences',
            'ui_preferences'
        ]

        for field in profile_fields:
            if f'profile.{field}' in validated_data:
                profile_data[field] = validated_data.pop(f'profile.{field}')

        # Update user fields
        for attr, value in validated_data.items():
            setattr(instance, attr, value)
        instance.save()

        # Update profile fields
        if profile_data:
            profile = getattr(instance, 'profile', None)
            if profile:
                for attr, value in profile_data.items():
                    setattr(profile, attr, value)
                profile.save()

        logger.info(
            "user_profile_updated",
            user_id=instance.id,
            username=instance.username,
            updated_fields=list(validated_data.keys()) + [f'profile.{k}' for k in profile_data.keys()]
        )

        return instance


class ChangePasswordSerializer(serializers.Serializer):
    """
    Serializer for password change requests.
    """

    current_password = serializers.CharField(
        max_length=128,
        style={'input_type': 'password'},
        help_text="Current password"
    )

    new_password = serializers.CharField(
        max_length=128,
        style={'input_type': 'password'},
        help_text="New password"
    )

    new_password_confirm = serializers.CharField(
        max_length=128,
        style={'input_type': 'password'},
        help_text="New password confirmation"
    )

    def validate_current_password(self, value):
        """Validate current password."""
        user = self.context.get('user')
        if user and not user.check_password(value):
            raise serializers.ValidationError("Current password is incorrect")
        return value

    def validate_new_password(self, value):
        """Validate new password strength."""
        try:
            validate_password(value)
        except ValidationError as e:
            raise serializers.ValidationError(list(e.messages))
        return value

    def validate(self, attrs):
        """Validate password confirmation and difference."""
        current_password = attrs.get('current_password')
        new_password = attrs.get('new_password')
        new_password_confirm = attrs.get('new_password_confirm')

        if new_password != new_password_confirm:
            raise serializers.ValidationError({
                'new_password_confirm': 'New passwords do not match'
            })

        if current_password == new_password:
            raise serializers.ValidationError({
                'new_password': 'New password must be different from current password'
            })

        return attrs


class ServiceTokenSerializer(serializers.Serializer):
    """
    Serializer for service token generation requests.
    """

    service_account_name = serializers.CharField(
        max_length=100,
        help_text="Name of the service account"
    )

    scopes = serializers.ListField(
        child=serializers.CharField(max_length=100),
        required=False,
        allow_empty=True,
        help_text="List of requested scopes"
    )

    def validate_service_account_name(self, value):
        """Validate service account exists."""
        from apps.users.models import ServiceAccount

        try:
            service_account = ServiceAccount.objects.get(
                name=value,
                is_active=True
            )
            if service_account.is_expired:
                raise serializers.ValidationError("Service account has expired")
        except ServiceAccount.DoesNotExist:
            raise serializers.ValidationError("Service account not found or inactive")

        return value


class PermissionCheckSerializer(serializers.Serializer):
    """
    Serializer for permission check requests.
    """

    permission = serializers.CharField(
        max_length=100,
        help_text="Permission codename to check"
    )

    service_name = serializers.CharField(
        max_length=100,
        help_text="Name of the service/application"
    )

    resource_id = serializers.CharField(
        max_length=255,
        required=False,
        allow_blank=True,
        help_text="Optional resource identifier"
    )

    context = serializers.JSONField(
        required=False,
        default=dict,
        help_text="Additional context for permission check"
    )

    def validate_permission(self, value):
        """Validate permission format."""
        if not value.strip():
            raise serializers.ValidationError("Permission cannot be empty")
        return value.strip()

    def validate_service_name(self, value):
        """Validate service name format."""
        if not value.strip():
            raise serializers.ValidationError("Service name cannot be empty")
        return value.strip()


class RoleSerializer(serializers.ModelSerializer):
    """
    Serializer for role management.
    """

    permissions_count = serializers.IntegerField(read_only=True)
    users_count = serializers.IntegerField(read_only=True)
    hierarchy_path = serializers.ListField(read_only=True)

    class Meta:
        from apps.authentication.models import Role
        model = Role
        fields = [
            'id', 'name', 'display_name', 'description',
            'parent_role', 'service_scope', 'is_system_role',
            'is_active', 'priority', 'permissions_count',
            'users_count', 'hierarchy_path', 'created_at',
            'updated_at', 'created_by'
        ]
        read_only_fields = [
            'id', 'is_system_role', 'permissions_count',
            'users_count', 'hierarchy_path', 'created_at',
            'updated_at', 'created_by'
        ]

    def validate_name(self, value):
        """Validate role name uniqueness."""
        if self.instance and self.instance.name == value:
            return value

        from apps.authentication.models import Role
        if Role.objects.filter(name=value).exists():
            raise serializers.ValidationError("Role name already exists")
        return value


class UserRoleSerializer(serializers.ModelSerializer):
    """
    Serializer for user role assignments.
    """

    role_name = serializers.CharField(source='role.name', read_only=True)
    role_display_name = serializers.CharField(source='role.display_name', read_only=True)
    user_username = serializers.CharField(source='user.username', read_only=True)
    user_email = serializers.CharField(source='user.email', read_only=True)
    assigned_by_username = serializers.CharField(source='assigned_by.username', read_only=True)

    class Meta:
        from apps.authentication.models import UserRole
        model = UserRole
        fields = [
            'id', 'user', 'role', 'scope_type', 'scope_id',
            'assigned_by', 'assigned_at', 'expires_at', 'is_active',
            'conditions', 'role_name', 'role_display_name',
            'user_username', 'user_email', 'assigned_by_username'
        ]
        read_only_fields = [
            'id', 'assigned_at', 'role_name', 'role_display_name',
            'user_username', 'user_email', 'assigned_by_username'
        ]

    def validate(self, attrs):
        """Validate role assignment."""
        user = attrs.get('user')
        role = attrs.get('role')
        scope_type = attrs.get('scope_type', 'global')
        scope_id = attrs.get('scope_id', '')

        # Check if assignment already exists
        from apps.authentication.models import UserRole
        if UserRole.objects.filter(
                user=user,
                role=role,
                scope_type=scope_type,
                scope_id=scope_id,
                is_active=True
        ).exists():
            raise serializers.ValidationError(
                "User already has this role assignment"
            )

        return attrs


class ServiceAccountSerializer(serializers.ModelSerializer):
    """
    Serializer for service account management.
    """

    api_key = serializers.UUIDField(read_only=True)
    is_expired = serializers.BooleanField(read_only=True)
    created_by_username = serializers.CharField(source='created_by.username', read_only=True)

    class Meta:
        from apps.users.models import ServiceAccount
        model = ServiceAccount
        fields = [
            'id', 'name', 'description', 'service_name',
            'api_key', 'allowed_ips', 'scopes', 'is_active',
            'expires_at', 'last_used', 'is_expired',
            'created_by', 'created_by_username', 'created_at',
            'updated_at'
        ]
        read_only_fields = [
            'id', 'api_key', 'last_used', 'is_expired',
            'created_by_username', 'created_at', 'updated_at'
        ]

    def validate_name(self, value):
        """Validate service account name uniqueness."""
        if self.instance and self.instance.name == value:
            return value

        from apps.users.models import ServiceAccount
        if ServiceAccount.objects.filter(name=value).exists():
            raise serializers.ValidationError("Service account name already exists")
        return value

    def validate_scopes(self, value):
        """Validate scopes format."""
        if not isinstance(value, list):
            raise serializers.ValidationError("Scopes must be a list")

        # Validate each scope
        for scope in value:
            if not isinstance(scope, str) or not scope.strip():
                raise serializers.ValidationError("Invalid scope format")

        return value

    def validate_allowed_ips(self, value):
        """Validate IP addresses format."""
        if not isinstance(value, list):
            raise serializers.ValidationError("Allowed IPs must be a list")

        # Basic IP validation - can be enhanced
        import ipaddress
        for ip in value:
            try:
                ipaddress.ip_address(ip)
            except ValueError:
                raise serializers.ValidationError(f"Invalid IP address: {ip}")

        return value


class AccessLogSerializer(serializers.ModelSerializer):
    """
    Serializer for access log entries.
    """

    user_username = serializers.CharField(source='user.username', read_only=True)
    service_account_name = serializers.CharField(source='service_account.name', read_only=True)

    class Meta:
        from apps.authentication.models import AccessLog
        model = AccessLog
        fields = [
            'id', 'user', 'service_account', 'action', 'resource',
            'service_name', 'permission_required', 'access_granted',
            'denial_reason', 'ip_address', 'user_agent',
            'additional_context', 'timestamp', 'user_username',
            'service_account_name'
        ]
        # Fix: Change from read_only_fields = '__all__' to a list
        read_only_fields = [
            'id', 'user', 'service_account', 'action', 'resource',
            'service_name', 'permission_required', 'access_granted',
            'denial_reason', 'ip_address', 'user_agent',
            'additional_context', 'timestamp', 'user_username',
            'service_account_name'
        ]


class UserSessionSerializer(serializers.ModelSerializer):
    """
    Serializer for user session management.
    """

    user_username = serializers.CharField(source='user.username', read_only=True)
    is_expired = serializers.BooleanField(read_only=True)

    class Meta:
        from apps.users.models import UserSession
        model = UserSession
        fields = [
            'id', 'user', 'session_key', 'device_info',
            'ip_address', 'location_info', 'is_active',
            'last_activity', 'created_at', 'expires_at',
            'user_username', 'is_expired'
        ]
        read_only_fields = [
            'id', 'user', 'session_key', 'last_activity',
            'created_at', 'user_username', 'is_expired'
        ]
