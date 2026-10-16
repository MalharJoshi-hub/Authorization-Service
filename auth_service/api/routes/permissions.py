"""Permissions API Router (Layer 5: API).

Provides discovery and registration of system-wide authorization permissions.
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
from auth_service.storage.postgres.permission_repo import PermissionRepository
from auth_service.storage.postgres.role_repo import RoleRepository
from auth_service.api.schemas.role_schemas import (
    PermissionCreateRequest,
    PermissionResponse,
)


router = APIRouter(prefix="/permissions", tags=["Permissions"])


@router.get(
    "",
    response_model=List[PermissionResponse],
    summary="List All Permissions",
    description="Lists all system and custom permissions.",
)
async def list_permissions(
    current_user: User = Depends(require_permission("permissions:read")),
    db: AsyncSession = Depends(get_db),
):
    perm_repo = PermissionRepository(db)
    perms = await perm_repo.list_permissions()
    return [
        PermissionResponse(
            id=p.id,
            name=p.name,
            resource=p.resource,
            action=p.action,
            description=p.description,
            created_at=p.created_at,
        )
        for p in perms
    ]


@router.post(
    "",
    response_model=PermissionResponse,
    status_code=status.HTTP_201_CREATED,
    summary="Create New Permission",
    description="Registers a new permission capability identifier.",
)
async def create_permission(
    payload: PermissionCreateRequest,
    current_user: User = Depends(require_permission("permissions:create")),
    db: AsyncSession = Depends(get_db),
):
    perm_repo = PermissionRepository(db)
    perm = await perm_repo.create(
        name=payload.name,
        resource=payload.resource,
        action=payload.action,
        description=payload.description,
    )
    return PermissionResponse(
        id=perm.id,
        name=perm.name,
        resource=perm.resource,
        action=perm.action,
        description=perm.description,
        created_at=perm.created_at,
    )
