"""Reusable FastAPI Route Dependencies (Core/Security).

Provides dependency injection for database sessions, Redis connections, current user
resolution, JWT decoding, blacklist validation, RBAC checks, and API Key verification.
"""

from typing import Any, Callable, Dict, List, Optional
from fastapi import Depends, Header, Request, Security
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from sqlalchemy.ext.asyncio import AsyncSession
from auth_service.config import settings
from auth_service.core.exceptions import (
    AuthenticationError,
    AuthorizationError,
    TokenBlacklistedError,
)
from auth_service.core.logger import request_id_ctx, tenant_id_ctx
from auth_service.core.rbac.checker import rbac_checker
from auth_service.core.security.jwt_handler import decode_token
from auth_service.core.security.token_blacklist import token_blacklist
from auth_service.core.security.api_keys import hash_api_key
from auth_service.models.user import User
from auth_service.models.api_key import APIKey
from auth_service.storage.postgres.database import get_db
from auth_service.storage.postgres.user_repo import UserRepository
from auth_service.storage.postgres.api_key_repo import APIKeyRepository


security_bearer = HTTPBearer(auto_error=False)


async def get_tenant_id(
    request: Request,
    x_tenant_id: Optional[str] = Header(None, alias="X-Tenant-ID"),
) -> str:
    """Resolve current tenant ID from header, request state, or global default."""
    if x_tenant_id:
        tenant_id = x_tenant_id.strip()
    elif hasattr(request.state, "tenant_id") and request.state.tenant_id:
        tenant_id = request.state.tenant_id
    else:
        tenant_id = settings.DEFAULT_TENANT_ID

    tenant_id_ctx.set(tenant_id)
    return tenant_id


async def get_token_payload(
    credentials: Optional[HTTPAuthorizationCredentials] = Security(security_bearer),
) -> Dict[str, Any]:
    """Extract and validate JWT access token claims."""
    if not credentials:
        raise AuthenticationError("Authorization header missing", code="MISSING_TOKEN")

    token = credentials.credentials
    # Cryptographically decode and verify signature
    payload = decode_token(token, expected_type="access")

    # Check JTI against Redis blacklist
    jti = payload.get("jti")
    if jti and await token_blacklist.is_blacklisted(jti):
        raise TokenBlacklistedError("Access token has been revoked")

    return payload


async def get_current_user(
    payload: Dict[str, Any] = Depends(get_token_payload),
    db: AsyncSession = Depends(get_db),
) -> User:
    """Resolve and authenticate current user entity from database."""
    user_id = payload.get("sub")
    tenant_id = payload.get("tenant_id")

    if not user_id:
        raise AuthenticationError("Invalid token subject", code="INVALID_TOKEN")

    repo = UserRepository(db)
    user = await repo.get_by_id(user_id, tenant_id=tenant_id)
    if not user:
        raise AuthenticationError("User associated with token no longer exists", code="USER_NOT_FOUND")

    if not user.is_active:
        raise AuthenticationError("User account has been deactivated", code="ACCOUNT_INACTIVE")

    return user


async def get_current_active_user(
    current_user: User = Depends(get_current_user),
) -> User:
    """Ensure authenticated user is active."""
    if not current_user.is_active:
        raise AuthenticationError("Account is suspended or deactivated", code="ACCOUNT_SUSPENDED")
    return current_user


async def get_current_verified_user(
    current_user: User = Depends(get_current_active_user),
) -> User:
    """Ensure authenticated user has verified their email address."""
    if not current_user.is_verified:
        raise AuthorizationError("Email verification required to access this resource", code="EMAIL_NOT_VERIFIED")
    return current_user


async def get_current_superuser(
    current_user: User = Depends(get_current_active_user),
) -> User:
    """Ensure authenticated user has superuser or superadmin privileges."""
    is_super = current_user.is_superuser
    if not is_super:
        user_roles = [r.name for r in current_user.roles]
        is_super = "superadmin" in user_roles

    if not is_super:
        raise AuthorizationError("Superuser access required", code="SUPERUSER_REQUIRED")
    return current_user


def require_role(role_name: str) -> Callable:
    """FastAPI dependency factory enforcing that user possesses a specific role."""
    async def role_checker(user: User = Depends(get_current_active_user)) -> User:
        user_roles = [r.name for r in user.roles]
        if not rbac_checker.has_role(user_roles, role_name):
            raise AuthorizationError(
                f"Role '{role_name}' is required to perform this action",
                code="INSUFFICIENT_ROLE",
            )
        return user

    return role_checker


def require_permission(permission_name: str) -> Callable:
    """FastAPI dependency factory enforcing that user possesses a specific permission."""
    async def permission_checker(
        user: User = Depends(get_current_active_user),
    ) -> User:
        # Collect all permissions associated with the user's assigned roles
        granted_perms: List[str] = []
        for role in user.roles:
            for p in role.permissions:
                granted_perms.append(p.name)

        if not rbac_checker.has_permission(granted_perms, permission_name):
            raise AuthorizationError(
                f"Permission '{permission_name}' is required to perform this action",
                code="INSUFFICIENT_PERMISSION",
            )
        return user

    return permission_checker


async def get_api_key_auth(
    x_api_key: Optional[str] = Header(None, alias="X-API-Key"),
    db: AsyncSession = Depends(get_db),
) -> APIKey:
    """Authenticate incoming machine-to-machine request via X-API-Key header."""
    if not x_api_key:
        raise AuthenticationError("API Key header 'X-API-Key' missing", code="MISSING_API_KEY")

    raw_key = x_api_key.strip()
    key_hash = hash_api_key(raw_key)

    repo = APIKeyRepository(db)
    api_key = await repo.get_by_hash(key_hash)
    if not api_key:
        raise AuthenticationError("Invalid or revoked API Key", code="INVALID_API_KEY")

    if not api_key.is_active:
        raise AuthenticationError("API Key has been revoked", code="API_KEY_REVOKED")

    await repo.update_last_used(api_key.id)
    return api_key
