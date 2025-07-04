from .ServiceAuthenticationService import ServiceAuthenticationService
from .PermissionService import PermissionService
from .JWTService import JWTService

jwt_service = JWTService()
permission_service = PermissionService()
service_auth_service = ServiceAuthenticationService()