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

from apps.authentication.services.JWTService import JWTService
from apps.authentication.services.PermissionService import PermissionService
from apps.users.models import ServiceAccount

# Configure structured logger
logger = structlog.get_logger(__name__)

User = get_user_model()


class ServiceAuthenticationService:
    """
    Service for handling service-to-service authentication.

    Provides authentication and authorization for microservice
    communication in the PSIM ecosystem.
    """

    def __init__(self):
        """Initialize service authentication service."""
        self.jwt_service = JWTService()
        self.permission_service = PermissionService()

    def authenticate_service_request(
            self,
            token: str,
            required_scope: Optional[str] = None,
            ip_address: Optional[str] = None
    ) -> Dict[str, Any]:
        """
        Authenticate service request using JWT token.

        Args:
            token: JWT token from service
            required_scope: Required scope for the operation
            ip_address: Service IP address

        Returns:
            Authentication result dictionary
        """
        # Validate token
        validation_result = self.jwt_service.validate_token(token)

        if not validation_result['valid']:
            return validation_result

        if validation_result['token_type'] != 'service':
            return {
                'valid': False,
                'error': 'Invalid token type for service authentication',
                'error_code': 'INVALID_TOKEN_TYPE'
            }

        service_account = validation_result['service_account']

        # Check IP restrictions
        if ip_address and not service_account.is_ip_allowed(ip_address):
            logger.warning(
                "service_auth_ip_denied",
                service_account=service_account.name,
                ip_address=ip_address,
                allowed_ips=service_account.allowed_ips
            )
            return {
                'valid': False,
                'error': 'IP address not allowed for this service account',
                'error_code': 'IP_NOT_ALLOWED'
            }

        # Check required scope if specified
        if required_scope:
            permission_result = self.permission_service.check_service_permission(
                service_account=service_account,
                permission=required_scope
            )

            if not permission_result['granted']:
                return {
                    'valid': False,
                    'error': f'Insufficient scope: {required_scope}',
                    'error_code': 'INSUFFICIENT_SCOPE'
                }

        # Record successful authentication
        service_account.record_usage(ip_address)

        logger.info(
            "service_authenticated",
            service_account=service_account.name,
            service_name=service_account.service_name,
            ip_address=ip_address,
            required_scope=required_scope
        )

        return {
            'valid': True,
            'service_account': service_account,
            'service_name': service_account.service_name,
            'scopes': validation_result['scopes'],
        }

    def validate_service_token(self, token: str, service_name: str) -> Dict[str, Any]:
        """
        Validate service token for backward compatibility.

        Args:
            token: Service token
            service_name: Name of the requesting service

        Returns:
            Validation results
        """
        return self.authenticate_service_request(token)

    def create_service_account(
            self,
            name: str,
            service_name: str,
            description: str,
            scopes: List[str],
            created_by: User,
            allowed_ips: Optional[List[str]] = None,
            expires_at: Optional[datetime] = None
    ) -> ServiceAccount:
        """
        Create new service account.

        Args:
            name: Service account name
            service_name: Microservice name
            description: Account description
            scopes: List of allowed scopes
            created_by: User creating the account
            allowed_ips: Allowed IP addresses
            expires_at: Optional expiration time

        Returns:
            ServiceAccount instance
        """
        service_account = ServiceAccount.objects.create(
            name=name,
            service_name=service_name,
            description=description,
            scopes=scopes,
            allowed_ips=allowed_ips or [],
            expires_at=expires_at,
            created_by=created_by
        )

        logger.info(
            "service_account_created",
            service_account=name,
            service_name=service_name,
            created_by=created_by.username,
            scopes=scopes
        )

        return service_account

    def generate_service_token(
            self,
            service_account_name: str,
            requested_scopes: Optional[List[str]] = None,
            ip_address: Optional[str] = None
    ) -> Dict[str, Any]:
        """
        Generate JWT token for service account.

        Args:
            service_account_name: Name of service account
            requested_scopes: Scopes to include in token
            ip_address: Service IP address

        Returns:
            Token generation result
        """
        try:
            service_account = ServiceAccount.objects.get(
                name=service_account_name,
                is_active=True
            )

            if service_account.is_expired:
                return {
                    'success': False,
                    'error': 'Service account has expired',
                    'error_code': 'SERVICE_ACCOUNT_EXPIRED'
                }

            token = self.jwt_service.generate_service_token(
                service_account=service_account,
                scopes=requested_scopes,
                ip_address=ip_address
            )

            return {
                'success': True,
                'token': token,
                'token_type': 'Bearer',
                'expires_in': self.jwt_service.service_token_lifetime,
                'scopes': service_account.scopes
            }

        except ServiceAccount.DoesNotExist:
            return {
                'success': False,
                'error': 'Service account not found',
                'error_code': 'SERVICE_ACCOUNT_NOT_FOUND'
            }



