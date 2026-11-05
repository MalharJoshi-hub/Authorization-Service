"""Machine API Keys API Router (Layer 5: API).

Manages machine-to-machine credentials, cryptographic key generation, scope bounds,
and revocation lifecycles.
"""

from datetime import datetime, timezone, timedelta
from typing import List
from fastapi import APIRouter, Depends, Request, status
from sqlalchemy.ext.asyncio import AsyncSession
from auth_service.core.dependencies import (
    get_current_active_user,
    get_db,
    get_tenant_id,
    require_permission,
)
from auth_service.core.exceptions import ResourceNotFoundError
from auth_service.core.security.api_keys import (
    generate_api_key,
    mask_api_key,
)
from auth_service.core.security.rate_limiter import get_client_ip
from auth_service.models.user import User
from auth_service.storage.postgres.api_key_repo import APIKeyRepository
from auth_service.storage.postgres.audit_log_repo import AuditLogRepository
from auth_service.api.schemas.api_key_schemas import (
    APIKeyCreateRequest,
    APIKeyCreatedResponse,
    APIKeyResponse,
)
from auth_service.api.schemas.common import MessageResponse


router = APIRouter(prefix="/api-keys", tags=["API Keys"])


@router.get(
    "",
    response_model=List[APIKeyResponse],
    summary="List API Keys",
    description="Lists all machine API keys issued for the tenant with masked secret tokens.",
)
async def list_api_keys(
    tenant_id: str = Depends(get_tenant_id),
    current_user: User = Depends(require_permission("api_keys:read")),
    db: AsyncSession = Depends(get_db),
):
    repo = APIKeyRepository(db)
    keys = await repo.list_keys(tenant_id)
    return [
        APIKeyResponse(
            id=k.id,
            tenant_id=k.tenant_id,
            name=k.name,
            prefix=k.prefix,
            masked_key=mask_api_key(k.prefix),
            scopes=k.scopes,
            is_active=k.is_active,
            last_used_at=k.last_used_at,
            expires_at=k.expires_at,
            created_at=k.created_at,
        )
        for k in keys
    ]


@router.post(
    "",
    response_model=APIKeyCreatedResponse,
    status_code=status.HTTP_201_CREATED,
    summary="Create API Key",
    description="Mints a new machine API key. The raw key is returned ONCE and cannot be recovered later.",
)
async def create_api_key(
    payload: APIKeyCreateRequest,
    request: Request,
    tenant_id: str = Depends(get_tenant_id),
    current_user: User = Depends(require_permission("api_keys:create")),
    db: AsyncSession = Depends(get_db),
):
    repo = APIKeyRepository(db)
    audit_repo = AuditLogRepository(db)

    # Generate high-entropy prefixed key
    raw_key, prefix, key_hash = generate_api_key(is_live=True)

    expires_at = None
    if payload.expires_in_days:
        expires_at = datetime.now(timezone.utc) + timedelta(days=payload.expires_in_days)

    key_record = await repo.create(
        tenant_id=tenant_id,
        name=payload.name,
        prefix=prefix,
        key_hash=key_hash,
        scopes=payload.scopes,
        user_id=current_user.id,
        expires_at=expires_at,
    )

    await audit_repo.log(
        tenant_id=tenant_id,
        event_type="api_key_created",
        user_id=current_user.id,
        ip_address=get_client_ip(request),
        user_agent=request.headers.get("user-agent"),
        status="success",
        details={"key_name": payload.name, "prefix": prefix, "scopes": payload.scopes},
    )

    return APIKeyCreatedResponse(
        id=key_record.id,
        name=key_record.name,
        prefix=key_record.prefix,
        raw_key=raw_key,
        scopes=key_record.scopes,
        expires_at=key_record.expires_at,
        created_at=key_record.created_at,
    )


@router.get(
    "/{key_id}",
    response_model=APIKeyResponse,
    summary="Get API Key Details",
    description="Inspects API key metadata by UUID.",
)
async def get_api_key(
    key_id: str,
    tenant_id: str = Depends(get_tenant_id),
    current_user: User = Depends(require_permission("api_keys:read")),
    db: AsyncSession = Depends(get_db),
):
    repo = APIKeyRepository(db)
    key = await repo.get_by_id(key_id, tenant_id=tenant_id)
    if not key:
        raise ResourceNotFoundError(f"API Key '{key_id}' not found")

    return APIKeyResponse(
        id=key.id,
        tenant_id=key.tenant_id,
        name=key.name,
        prefix=key.prefix,
        masked_key=mask_api_key(key.prefix),
        scopes=key.scopes,
        is_active=key.is_active,
        last_used_at=key.last_used_at,
        expires_at=key.expires_at,
        created_at=key.created_at,
    )


@router.delete(
    "/{key_id}",
    response_model=MessageResponse,
    summary="Revoke API Key",
    description="Deactivates an API key, instantly denying subsequent authentication requests.",
)
async def revoke_api_key(
    key_id: str,
    request: Request,
    tenant_id: str = Depends(get_tenant_id),
    current_user: User = Depends(require_permission("api_keys:delete")),
    db: AsyncSession = Depends(get_db),
):
    repo = APIKeyRepository(db)
    audit_repo = AuditLogRepository(db)

    await repo.revoke(key_id, tenant_id=tenant_id)

    await audit_repo.log(
        tenant_id=tenant_id,
        event_type="api_key_revoked",
        user_id=current_user.id,
        ip_address=get_client_ip(request),
        user_agent=request.headers.get("user-agent"),
        status="success",
        details={"key_id": key_id},
    )

    return MessageResponse(message=f"API Key '{key_id}' successfully revoked.")

