"""SQLAlchemy Data Model Definitions (Layer 4).

Exports all entity tables and relationships for the Auth-as-a-Service system.
"""

from auth_service.models.base import Base
from auth_service.models.associations import user_roles, role_permissions
from auth_service.models.tenant import Tenant
from auth_service.models.permission import Permission
from auth_service.models.role import Role
from auth_service.models.user import User
from auth_service.models.token import RefreshToken
from auth_service.models.api_key import APIKey
from auth_service.models.audit_log import AuditLog
from auth_service.models.oauth_account import OAuthAccount
from auth_service.models.mfa import UserMFA
from auth_service.models.session import UserSession
from auth_service.models.webhook import WebhookEndpoint

__all__ = [
    "Base",
    "user_roles",
    "role_permissions",
    "Tenant",
    "Permission",
    "Role",
    "User",
    "RefreshToken",
    "APIKey",
    "AuditLog",
    "OAuthAccount",
    "UserMFA",
    "UserSession",
    "WebhookEndpoint",
]
