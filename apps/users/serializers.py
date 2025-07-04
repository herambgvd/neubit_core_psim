"""
Serializers for user management APIs.

This module provides DRF serializers for user-related API endpoints.
"""

import structlog
from django.contrib.auth import get_user_model
from django.contrib.auth.password_validation import validate_password
from django.core.exceptions import ValidationError
from rest_framework import serializers

# Configure structured logger
logger = structlog.get_logger(__name__)

User = get_user_model()


class UserSerializer(serializers.ModelSerializer):
    """
    Serializer for user management.

    Provides comprehensive user information including profile data.
    """

    # Profile fields
    avatar_url = serializers.SerializerMethodField()
    bio = serializers.CharField(source='profile.bio', read_only=True)
    date_of_birth = serializers.DateField(source='profile.date_of_birth', read_only=True)
    hire_date = serializers.DateField(source='profile.hire_date', read_only=True)
    office_location = serializers.CharField(source='profile.office_location', read_only=True)

    # Computed fields
    full_name = serializers.CharField(read_only=True)
    manager_name = serializers.CharField(source='manager.get_full_name', read_only=True)
    subordinates_count = serializers.SerializerMethodField()
    active_roles_count = serializers.SerializerMethodField()

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
            'full_name', 'employee_id', 'phone_number', 'department',
            'job_title', 'manager', 'manager_name', 'timezone', 'language',
            'is_active', 'is_staff', 'is_superuser', 'is_service_account',
            'last_login', 'is_account_locked', 'password_age_days',
            'force_password_change', 'created_at', 'updated_at',
            # Profile fields
            'avatar_url', 'bio', 'date_of_birth', 'hire_date', 'office_location',
            # Computed fields
            'subordinates_count', 'active_roles_count'
        ]
        read_only_fields = [
            'id', 'uuid', 'username', 'is_staff', 'is_superuser',
            'is_service_account', 'last_login', 'is_account_locked',
            'password_age_days', 'force_password_change',
            'created_at', 'updated_at', 'full_name', 'manager_name',
            'subordinates_count', 'active_roles_count'
        ]

    def get_avatar_url(self, obj):
        """Get avatar URL if available."""
        if hasattr(obj, 'profile') and obj.profile.avatar:
            request = self.context.get('request')
            if request:
                return request.build_absolute_uri(obj.profile.avatar.url)
            return obj.profile.avatar.url
        return None

    def get_subordinates_count(self, obj):
        """Get count of subordinates."""
        return obj.subordinates.count() if hasattr(obj, 'subordinates') else 0

    def get_active_roles_count(self, obj):
        """Get count of active role assignments."""
        return obj.user_roles.filter(is_active=True).count() if hasattr(obj, 'user_roles') else 0

    def validate_email(self, value):
        """Validate email uniqueness (excluding current user)."""
        if self.instance and self.instance.email == value:
            return value

        if User.objects.filter(email=value).exists():
            raise serializers.ValidationError("Email address already in use")
        return value

    def validate_employee_id(self, value):
        """Validate employee ID uniqueness (excluding current user)."""
        if not value:  # Allow empty employee ID
            return value

        if self.instance and self.instance.employee_id == value:
            return value

        if User.objects.filter(employee_id=value).exists():
            raise serializers.ValidationError("Employee ID already in use")
        return value

    def validate_manager(self, value):
        """Validate manager assignment."""
        if value and self.instance and value == self.instance:
            raise serializers.ValidationError("User cannot be their own manager")
        return value


class UserCreateSerializer(serializers.ModelSerializer):
    """
    Serializer for user creation.

    Handles user creation with password validation and profile setup.
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
            'password', 'password_confirm', 'employee_id',
            'phone_number', 'department', 'job_title',
            'manager', 'timezone', 'language', 'is_active',
            'is_staff'
        ]
        extra_kwargs = {
            'email': {'required': True},
            'first_name': {'required': True},
            'last_name': {'required': True},
        }

    def validate_username(self, value):
        """Validate username uniqueness."""
        if User.objects.filter(username=value).exists():
            raise serializers.ValidationError("Username already exists")
        return value

    def validate_email(self, value):
        """Validate email uniqueness."""
        if User.objects.filter(email=value).exists():
            raise serializers.ValidationError("Email address already registered")
        return value

    def validate_employee_id(self, value):
        """Validate employee ID uniqueness."""
        if value and User.objects.filter(employee_id=value).exists():
            raise serializers.ValidationError("Employee ID already in use")
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
            "user_created_via_admin_api",
            user_id=user.id,
            username=user.username,
            email=user.email,
            created_by=self.context.get('request').user.username if self.context.get('request') else 'system'
        )

        return user


class UserListSerializer(serializers.ModelSerializer):
    """
    Lightweight serializer for user lists.

    Provides essential user information for list views.
    """

    full_name = serializers.CharField(read_only=True)
    avatar_url = serializers.SerializerMethodField()
    manager_name = serializers.CharField(source='manager.get_full_name', read_only=True)
    active_roles_count = serializers.SerializerMethodField()

    class Meta:
        model = User
        fields = [
            'id', 'uuid', 'username', 'email', 'full_name',
            'employee_id', 'department', 'job_title',
            'manager_name', 'is_active', 'is_staff',
            'last_login', 'avatar_url', 'active_roles_count'
        ]

    def get_avatar_url(self, obj):
        """Get avatar URL if available."""
        if hasattr(obj, 'profile') and obj.profile.avatar:
            request = self.context.get('request')
            if request:
                return request.build_absolute_uri(obj.profile.avatar.url)
            return obj.profile.avatar.url
        return None

    def get_active_roles_count(self, obj):
        """Get count of active role assignments."""
        return obj.user_roles.filter(is_active=True).count() if hasattr(obj, 'user_roles') else 0


class UserProfileUpdateSerializer(serializers.ModelSerializer):
    """
    Serializer for updating user profile information.

    Allows updating both user and profile fields.
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

    class Meta:
        model = User
        fields = [
            'first_name', 'last_name', 'email', 'phone_number',
            'department', 'job_title', 'timezone', 'language',
            # Profile fields
            'avatar', 'bio', 'date_of_birth', 'address',
            'emergency_contact_name', 'emergency_contact_phone',
            'hire_date', 'office_location', 'notification_preferences',
            'ui_preferences'
        ]

    def validate_email(self, value):
        """Validate email uniqueness (excluding current user)."""
        if self.instance and self.instance.email == value:
            return value

        if User.objects.filter(email=value).exists():
            raise serializers.ValidationError("Email address already in use")
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
            "user_profile_updated_via_api",
            user_id=instance.id,
            username=instance.username,
            updated_fields=list(validated_data.keys()) + [f'profile.{k}' for k in profile_data.keys()],
            updated_by=self.context.get('request').user.username if self.context.get('request') else 'system'
        )

        return instance


class UserActivitySerializer(serializers.Serializer):
    """
    Serializer for user activity information.

    Provides read-only activity data for users.
    """

    user_id = serializers.IntegerField(read_only=True)
    username = serializers.CharField(read_only=True)
    last_login = serializers.DateTimeField(read_only=True)
    login_count_30d = serializers.IntegerField(read_only=True)
    failed_login_count_30d = serializers.IntegerField(read_only=True)
    active_sessions = serializers.IntegerField(read_only=True)
    last_activity = serializers.DateTimeField(read_only=True)
    account_status = serializers.DictField(read_only=True)


class BulkUserActionSerializer(serializers.Serializer):
    """
    Serializer for bulk user operations.

    Handles bulk activation, deactivation, and role assignments.
    """

    user_ids = serializers.ListField(
        child=serializers.IntegerField(),
        min_length=1,
        help_text="List of user IDs to perform action on"
    )

    action = serializers.ChoiceField(
        choices=[
            ('activate', 'Activate Users'),
            ('deactivate', 'Deactivate Users'),
            ('assign_role', 'Assign Role'),
            ('revoke_role', 'Revoke Role'),
            ('reset_password', 'Reset Password')
        ],
        help_text="Action to perform on selected users"
    )

    # Optional fields for specific actions
    role_id = serializers.IntegerField(
        required=False,
        help_text="Role ID for assign_role/revoke_role actions"
    )

    new_password = serializers.CharField(
        required=False,
        help_text="New password for reset_password action"
    )

    force_password_change = serializers.BooleanField(
        default=True,
        help_text="Force password change on next login"
    )

    def validate(self, attrs):
        """Validate action-specific requirements."""
        action = attrs.get('action')

        if action in ['assign_role', 'revoke_role']:
            if not attrs.get('role_id'):
                raise serializers.ValidationError({
                    'role_id': 'Role ID is required for role actions'
                })

        if action == 'reset_password':
            if not attrs.get('new_password'):
                raise serializers.ValidationError({
                    'new_password': 'New password is required for reset password action'
                })

            # Validate password strength
            try:
                validate_password(attrs['new_password'])
            except ValidationError as e:
                raise serializers.ValidationError({
                    'new_password': list(e.messages)
                })

        return attrs
