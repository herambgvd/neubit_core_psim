"""
Authentication services for Core Platform Service.

This module provides comprehensive authentication services including
JWT token management, service-to-service authentication, and
RBAC permission validation.
"""

import uuid
from datetime import datetime, timedelta
from typing import Dict, Any, Optional, List

import jwt
import structlog
from django.conf import settings
from django.contrib.auth import get_user_model
from django.core.cache import cache
from django.utils import timezone

from apps.users.models import ServiceAccount, UserSession

# Configure structured logger
logger = structlog.get_logger(__name__)

User = get_user_model()


class JWTService:
    """
    JWT token management service.

    Handles JWT token generation, validation, and refresh for both
    user authentication and service-to-service communication.
    """

    def __init__(self):
        """Initialize JWT service with configuration."""
        self.jwt_settings = getattr(settings, 'JWT_SETTINGS', {})
        self.secret_key = settings.SECRET_KEY
        self.algorithm = self.jwt_settings.get('ALGORITHM', 'HS256')
        self.access_token_lifetime = self.jwt_settings.get('ACCESS_TOKEN_LIFETIME', 15 * 60)  # 15 minutes
        self.refresh_token_lifetime = self.jwt_settings.get('REFRESH_TOKEN_LIFETIME', 7 * 24 * 60 * 60)  # 7 days
        self.service_token_lifetime = self.jwt_settings.get('SERVICE_TOKEN_LIFETIME', 24 * 60 * 60)  # 24 hours
        self.issuer = self.jwt_settings.get('ISSUER', 'neubit-psim-core')
        self.audience = self.jwt_settings.get('AUDIENCE', 'neubit-psim-services')

    def generate_user_tokens(
            self,
            user: User,
            session_key: Optional[str] = None,
            device_info: Optional[Dict] = None,
            ip_address: Optional[str] = None
    ) -> Dict[str, str]:
        """
        Generate access and refresh tokens for a user.

        Args:
            user: User instance
            session_key: Session key for tracking
            device_info: Device information
            ip_address: Client IP address

        Returns:
            Dictionary containing access_token and refresh_token
        """
        now = timezone.now()
        user_data = {
            'user_id': user.id,
            'username': user.username,
            'email': user.email,
            'uuid': str(user.uuid),
            'is_staff': user.is_staff,
            'is_superuser': user.is_superuser,
        }

        # Generate access token
        access_payload = {
            'type': 'access',
            'user_data': user_data,
            'iat': now.timestamp(),
            'exp': (now + timedelta(seconds=self.access_token_lifetime)).timestamp(),
            'iss': self.issuer,
            'aud': self.audience,
            'jti': str(uuid.uuid4()),
        }

        if session_key:
            access_payload['session_key'] = session_key

        # Generate refresh token
        refresh_jti = str(uuid.uuid4())
        refresh_payload = {
            'type': 'refresh',
            'user_id': user.id,
            'iat': now.timestamp(),
            'exp': (now + timedelta(seconds=self.refresh_token_lifetime)).timestamp(),
            'iss': self.issuer,
            'aud': self.audience,
            'jti': refresh_jti,
        }

        access_token = jwt.encode(access_payload, self.secret_key, algorithm=self.algorithm)
        refresh_token = jwt.encode(refresh_payload, self.secret_key, algorithm=self.algorithm)

        # Store refresh token in cache for validation
        cache.set(
            f"refresh_token:{refresh_jti}",
            {
                'user_id': user.id,
                'session_key': session_key,
                'device_info': device_info or {},
                'ip_address': ip_address,
                'created_at': now.isoformat(),
            },
            timeout=self.refresh_token_lifetime
        )

        # Create user session if session_key provided
        if session_key:
            self._create_user_session(
                user=user,
                session_key=session_key,
                device_info=device_info or {},
                ip_address=ip_address,
                expires_at=now + timedelta(seconds=self.refresh_token_lifetime)
            )

        logger.info(
            "user_tokens_generated",
            user_id=user.id,
            username=user.username,
            session_key=session_key,
            ip_address=ip_address
        )

        return {
            'access_token': access_token,
            'refresh_token': refresh_token,
            'token_type': 'Bearer',
            'expires_in': self.access_token_lifetime,
        }

    def generate_service_token(
            self,
            service_account: ServiceAccount,
            scopes: Optional[List[str]] = None,
            ip_address: Optional[str] = None
    ) -> str:
        """
        Generate JWT token for service-to-service authentication.

        Args:
            service_account: Service account instance
            scopes: List of requested scopes
            ip_address: Service IP address

        Returns:
            JWT token string
        """
        now = timezone.now()

        # Validate requested scopes
        allowed_scopes = scopes or []
        if scopes:
            allowed_scopes = [
                scope for scope in scopes
                if service_account.has_scope(scope)
            ]

        payload = {
            'type': 'service',
            'service_account_id': service_account.id,
            'service_name': service_account.service_name,
            'account_name': service_account.name,
            'scopes': allowed_scopes,
            'iat': now.timestamp(),
            'exp': (now + timedelta(seconds=self.service_token_lifetime)).timestamp(),
            'iss': self.issuer,
            'aud': self.audience,
            'jti': str(uuid.uuid4()),
        }

        token = jwt.encode(payload, self.secret_key, algorithm=self.algorithm)

        # Record service account usage
        service_account.record_usage(ip_address)

        logger.info(
            "service_token_generated",
            service_account=service_account.name,
            service_name=service_account.service_name,
            scopes=allowed_scopes,
            ip_address=ip_address
        )

        return token

    def validate_token(self, token: str) -> Dict[str, Any]:
        """
        Validate JWT token and return payload.

        Args:
            token: JWT token string

        Returns:
            Dictionary with validation results
        """
        try:
            payload = jwt.decode(
                token,
                self.secret_key,
                algorithms=[self.algorithm],
                audience=self.audience,
                issuer=self.issuer
            )

            token_type = payload.get('type')

            if token_type == 'access':
                return self._validate_access_token(payload)
            elif token_type == 'service':
                return self._validate_service_token(payload)
            elif token_type == 'refresh':
                return self._validate_refresh_token(payload)
            else:
                return {
                    'valid': False,
                    'error': 'Invalid token type',
                    'error_code': 'INVALID_TOKEN_TYPE'
                }

        except jwt.ExpiredSignatureError:
            return {
                'valid': False,
                'error': 'Token has expired',
                'error_code': 'TOKEN_EXPIRED'
            }
        except jwt.InvalidTokenError as e:
            return {
                'valid': False,
                'error': f'Invalid token: {str(e)}',
                'error_code': 'INVALID_TOKEN'
            }
        except Exception as e:
            logger.error("token_validation_error", error=str(e))
            return {
                'valid': False,
                'error': 'Token validation failed',
                'error_code': 'VALIDATION_ERROR'
            }

    def refresh_access_token(self, refresh_token: str) -> Dict[str, Any]:
        """
        Generate new access token using refresh token.

        Args:
            refresh_token: Refresh token string

        Returns:
            Dictionary with new tokens or error
        """
        validation_result = self.validate_token(refresh_token)

        if not validation_result['valid']:
            return validation_result

        if validation_result['token_type'] != 'refresh':
            return {
                'valid': False,
                'error': 'Invalid token type for refresh',
                'error_code': 'INVALID_TOKEN_TYPE'
            }

        try:
            user = User.objects.get(id=validation_result['user_id'])

            # Generate new tokens
            new_tokens = self.generate_user_tokens(
                user=user,
                session_key=validation_result.get('session_key'),
                device_info=validation_result.get('device_info'),
                ip_address=validation_result.get('ip_address')
            )

            # Invalidate old refresh token if rotation is enabled
            if self.jwt_settings.get('ROTATE_REFRESH_TOKENS', True):
                cache.delete(f"refresh_token:{validation_result['jti']}")

            logger.info(
                "access_token_refreshed",
                user_id=user.id,
                username=user.username
            )

            return {
                'valid': True,
                **new_tokens
            }

        except User.DoesNotExist:
            return {
                'valid': False,
                'error': 'User not found',
                'error_code': 'USER_NOT_FOUND'
            }

    def revoke_token(self, token: str, reason: str = "manual_revocation") -> bool:
        """
        Revoke a JWT token.

        Args:
            token: Token to revoke
            reason: Reason for revocation

        Returns:
            True if token was revoked successfully
        """
        try:
            payload = jwt.decode(
                token,
                self.secret_key,
                algorithms=[self.algorithm],
                options={"verify_exp": False}  # Allow expired tokens for revocation
            )

            jti = payload.get('jti')
            if not jti:
                return False

            # Add to blacklist
            cache.set(
                f"blacklisted_token:{jti}",
                {
                    'revoked_at': timezone.now().isoformat(),
                    'reason': reason,
                    'token_type': payload.get('type', 'unknown')
                },
                timeout=86400 * 30  # Keep blacklist for 30 days
            )

            # If it's a refresh token, also remove from active tokens
            if payload.get('type') == 'refresh':
                cache.delete(f"refresh_token:{jti}")

            logger.info(
                "token_revoked",
                jti=jti,
                token_type=payload.get('type'),
                reason=reason
            )

            return True

        except Exception as e:
            logger.error("token_revocation_error", error=str(e))
            return False

    def _validate_access_token(self, payload: Dict[str, Any]) -> Dict[str, Any]:
        """Validate access token payload."""
        # Check if token is blacklisted
        jti = payload.get('jti')
        if jti and cache.get(f"blacklisted_token:{jti}"):
            return {
                'valid': False,
                'error': 'Token has been revoked',
                'error_code': 'TOKEN_REVOKED'
            }

        user_data = payload.get('user_data', {})
        user_id = user_data.get('user_id')

        if not user_id:
            return {
                'valid': False,
                'error': 'Invalid user data in token',
                'error_code': 'INVALID_USER_DATA'
            }

        # Verify user still exists and is active
        try:
            user = User.objects.get(id=user_id, is_active=True)

            # Check if account is locked
            if user.is_account_locked:
                return {
                    'valid': False,
                    'error': 'User account is locked',
                    'error_code': 'ACCOUNT_LOCKED'
                }

            return {
                'valid': True,
                'token_type': 'access',
                'user': user,
                'user_data': user_data,
                'session_key': payload.get('session_key'),
                'jti': jti,
            }

        except User.DoesNotExist:
            return {
                'valid': False,
                'error': 'User not found or inactive',
                'error_code': 'USER_NOT_FOUND'
            }

    def _validate_service_token(self, payload: Dict[str, Any]) -> Dict[str, Any]:
        """Validate service token payload."""
        # Check if token is blacklisted
        jti = payload.get('jti')
        if jti and cache.get(f"blacklisted_token:{jti}"):
            return {
                'valid': False,
                'error': 'Token has been revoked',
                'error_code': 'TOKEN_REVOKED'
            }

        service_account_id = payload.get('service_account_id')

        if not service_account_id:
            return {
                'valid': False,
                'error': 'Invalid service account data in token',
                'error_code': 'INVALID_SERVICE_DATA'
            }

        try:
            service_account = ServiceAccount.objects.get(
                id=service_account_id,
                is_active=True
            )

            # Check if service account has expired
            if service_account.is_expired:
                return {
                    'valid': False,
                    'error': 'Service account has expired',
                    'error_code': 'SERVICE_ACCOUNT_EXPIRED'
                }

            return {
                'valid': True,
                'token_type': 'service',
                'service_account': service_account,
                'service_name': payload.get('service_name'),
                'scopes': payload.get('scopes', []),
                'jti': jti,
            }

        except ServiceAccount.DoesNotExist:
            return {
                'valid': False,
                'error': 'Service account not found or inactive',
                'error_code': 'SERVICE_ACCOUNT_NOT_FOUND'
            }

    def _validate_refresh_token(self, payload: Dict[str, Any]) -> Dict[str, Any]:
        """Validate refresh token payload."""
        jti = payload.get('jti')

        if not jti:
            return {
                'valid': False,
                'error': 'Invalid refresh token',
                'error_code': 'INVALID_REFRESH_TOKEN'
            }

        # Check if token is blacklisted
        if cache.get(f"blacklisted_token:{jti}"):
            return {
                'valid': False,
                'error': 'Token has been revoked',
                'error_code': 'TOKEN_REVOKED'
            }

        # Get refresh token data from cache
        refresh_data = cache.get(f"refresh_token:{jti}")

        if not refresh_data:
            return {
                'valid': False,
                'error': 'Refresh token not found or expired',
                'error_code': 'REFRESH_TOKEN_NOT_FOUND'
            }

        user_id = payload.get('user_id')

        if user_id != refresh_data.get('user_id'):
            return {
                'valid': False,
                'error': 'Token mismatch',
                'error_code': 'TOKEN_MISMATCH'
            }

        return {
            'valid': True,
            'token_type': 'refresh',
            'user_id': user_id,
            'session_key': refresh_data.get('session_key'),
            'device_info': refresh_data.get('device_info'),
            'ip_address': refresh_data.get('ip_address'),
            'jti': jti,
        }

    def _create_user_session(
            self,
            user: User,
            session_key: str,
            device_info: Dict,
            ip_address: Optional[str],
            expires_at: datetime
    ):
        """Create or update user session."""
        try:
            session, created = UserSession.objects.get_or_create(
                session_key=session_key,
                defaults={
                    'user': user,
                    'device_info': device_info,
                    'ip_address': ip_address or '0.0.0.0',
                    'expires_at': expires_at,
                }
            )

            if not created:
                # Update existing session
                session.last_activity = timezone.now()
                session.is_active = True
                session.save(update_fields=['last_activity', 'is_active'])

        except Exception as e:
            logger.error("session_creation_error", error=str(e))



