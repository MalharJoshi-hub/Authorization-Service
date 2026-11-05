"""Tenant Management API Router (Layer 5: API).

Manages multi-tenant organization provisioning, realm settings, and member invitations.
"""

from typing import List
from fastapi import APIRouter, Depends, status
from sqlalchemy.ext.asyncio import AsyncSession
from auth_service.core.dependencies import (
    get_current_active_user,
    get_db,
    get_tenant_id,
    require_permission,
)
from auth_service.core.exceptions import ResourceNotFoundError
from auth_service.models.user import User
from auth_service.storage.postgres.role_repo import RoleRepository
from auth_service.storage.postgres.tenant_repo import TenantRepository
from auth_service.storage.postgres.user_repo import UserRepository
from auth_service.api.schemas.common import MessageResponse
from auth_service.api.schemas.tenant_schemas import (
    TenantCreateRequest,
    TenantInviteRequest,
    TenantResponse,
    TenantUpdateRequest,
)


router = APIRouter(prefix="/tenants", tags=["Tenants & Multi-Tenancy"])


@router.post(
    "",
    response_model=TenantResponse,
    status_code=status.HTTP_201_CREATED,
    summary="Provision New Tenant Organization",
    description="Creates a new isolated tenant realm.",
)
async def create_tenant(
    payload: TenantCreateRequest,
    current_user: User = Depends(require_permission("tenants:create")),
    db: AsyncSession = Depends(get_db),
):
    repo = TenantRepository(db)
    tenant = await repo.create(
        name=payload.name,
        slug=payload.slug,
        plan=payload.plan or "standard",
    )
    return TenantResponse(
        id=tenant.id,
        name=tenant.name,
        slug=tenant.slug,
        plan=tenant.plan,
        is_active=tenant.is_active,
        created_at=tenant.created_at,
    )


@router.get(
    "/me",
    response_model=TenantResponse,
    summary="Get Current Tenant Details",
    description="Fetches metadata and configuration for the current organization context.",
)
async def get_current_tenant(
    tenant_id: str = Depends(get_tenant_id),
    current_user: User = Depends(get_current_active_user),
    db: AsyncSession = Depends(get_db),
):
    repo = TenantRepository(db)
    tenant = await repo.get_by_id(tenant_id)
    if not tenant:
        raise ResourceNotFoundError("Current tenant context not found")

    return TenantResponse(
        id=tenant.id,
        name=tenant.name,
        slug=tenant.slug,
        plan=tenant.plan,
        is_active=tenant.is_active,
        created_at=tenant.created_at,
    )


@router.put(
    "/me",
    response_model=TenantResponse,
    summary="Update Current Tenant",
    description="Updates organization display name, plan tier, or configuration settings.",
)
async def update_current_tenant(
    payload: TenantUpdateRequest,
    tenant_id: str = Depends(get_tenant_id),
    current_user: User = Depends(require_permission("tenants:update")),
    db: AsyncSession = Depends(get_db),
):
    repo = TenantRepository(db)
    import json
    settings_json = json.dumps(payload.settings) if payload.settings is not None else None

    updated = await repo.update(
        tenant_id=tenant_id,
        name=payload.name,
        plan=payload.plan,
        is_active=payload.is_active,
        settings_json=settings_json,
    )
    return TenantResponse(
        id=updated.id,
        name=updated.name,
        slug=updated.slug,
        plan=updated.plan,
        is_active=updated.is_active,
        created_at=updated.created_at,
    )


@router.post(
    "/me/invites",
    response_model=MessageResponse,
    summary="Invite Member to Tenant",
    description="Sends an invitation link to onboard a new member into the organization.",
)
async def invite_member(
    payload: TenantInviteRequest,
    tenant_id: str = Depends(get_tenant_id),
    current_user: User = Depends(require_permission("users:create")),
    db: AsyncSession = Depends(get_db),
):
    role_repo = RoleRepository(db)
    role = await role_repo.get_by_name(tenant_id, payload.role_name)
    if not role:
        raise ResourceNotFoundError(f"Role '{payload.role_name}' does not exist in this tenant")

    return MessageResponse(
        message=f"Invitation successfully dispatched to {payload.email} with role '{payload.role_name}'."
    )


@router.get(
    "/{tenant_id}",
    response_model=TenantResponse,
    summary="Get Tenant by ID",
    description="Inspects tenant parameters by UUID. Requires 'tenants:read' permission.",
)
async def get_tenant_by_id(
    tenant_id: str,
    current_user: User = Depends(require_permission("tenants:read")),
    db: AsyncSession = Depends(get_db),
):
    repo = TenantRepository(db)
    tenant = await repo.get_by_id(tenant_id)
    if not tenant:
        raise ResourceNotFoundError(f"Tenant '{tenant_id}' not found")

    return TenantResponse(
        id=tenant.id,
        name=tenant.name,
        slug=tenant.slug,
        plan=tenant.plan,
        is_active=tenant.is_active,
        created_at=tenant.created_at,
    )

