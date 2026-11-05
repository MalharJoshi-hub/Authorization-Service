"""Role-Based Access Control API Router (Layer 5: API).

Manages roles, permission grants, user assignments, and tenant role hierarchies.
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
from auth_service.storage.postgres.user_repo import UserRepository
from auth_service.api.schemas.common import MessageResponse
from auth_service.api.schemas.role_schemas import (
    AssignPermissionsRequest,
    PermissionResponse,
    RoleCreateRequest,
    RoleResponse,
    RoleUpdateRequest,
)


router = APIRouter(prefix="/roles", tags=["Roles & RBAC"])


def serialize_role(role) -> RoleResponse:
    perms = [
        PermissionResponse(
            id=p.id,
            name=p.name,
            resource=p.resource,
            action=p.action,
            description=p.description,
            created_at=p.created_at,
        )
        for p in role.permissions
    ]
    return RoleResponse(
        id=role.id,
        tenant_id=role.tenant_id,
        name=role.name,
        description=role.description,
        is_system=role.is_system,
        permissions=perms,
        created_at=role.created_at,
    )


@router.get(
    "",
    response_model=List[RoleResponse],
    summary="List Tenant Roles",
    description="Lists all roles configured within the tenant boundary.",
)
async def list_roles(
    tenant_id: str = Depends(get_tenant_id),
    current_user: User = Depends(require_permission("roles:read")),
    db: AsyncSession = Depends(get_db),
):
    role_repo = RoleRepository(db)
    roles = await role_repo.list_roles(tenant_id)
    return [serialize_role(r) for r in roles]


@router.post(
    "",
    response_model=RoleResponse,
    status_code=status.HTTP_201_CREATED,
    summary="Create Custom Role",
    description="Registers a new custom role with optional initial permissions.",
)
async def create_role(
    payload: RoleCreateRequest,
    tenant_id: str = Depends(get_tenant_id),
    current_user: User = Depends(require_permission("roles:create")),
    db: AsyncSession = Depends(get_db),
):
    role_repo = RoleRepository(db)
    perm_repo = PermissionRepository(db)

    perms = []
    if payload.permission_names:
        perms = await perm_repo.get_by_names(payload.permission_names)

    role = await role_repo.create(
        tenant_id=tenant_id,
        name=payload.name,
        description=payload.description,
        is_system=False,
        permissions=perms,
    )
    return serialize_role(role)


@router.get(
    "/{role_id}",
    response_model=RoleResponse,
    summary="Get Role Details",
    description="Fetches role metadata and bound permissions by UUID.",
)
async def get_role(
    role_id: str,
    tenant_id: str = Depends(get_tenant_id),
    current_user: User = Depends(require_permission("roles:read")),
    db: AsyncSession = Depends(get_db),
):
    role_repo = RoleRepository(db)
    role = await role_repo.get_by_id(role_id, tenant_id=tenant_id)
    if not role:
        raise ResourceNotFoundError(f"Role '{role_id}' not found")
    return serialize_role(role)


@router.put(
    "/{role_id}",
    response_model=RoleResponse,
    summary="Update Role",
    description="Updates role name and description.",
)
async def update_role(
    role_id: str,
    payload: RoleUpdateRequest,
    tenant_id: str = Depends(get_tenant_id),
    current_user: User = Depends(require_permission("roles:update")),
    db: AsyncSession = Depends(get_db),
):
    role_repo = RoleRepository(db)
    updated = await role_repo.update(
        role_id=role_id,
        tenant_id=tenant_id,
        name=payload.name,
        description=payload.description,
    )
    return serialize_role(updated)


@router.delete(
    "/{role_id}",
    response_model=MessageResponse,
    summary="Delete Role",
    description="Deletes a custom role (system roles cannot be removed).",
)
async def delete_role(
    role_id: str,
    tenant_id: str = Depends(get_tenant_id),
    current_user: User = Depends(require_permission("roles:delete")),
    db: AsyncSession = Depends(get_db),
):
    role_repo = RoleRepository(db)
    await role_repo.delete(role_id, tenant_id=tenant_id)
    return MessageResponse(message=f"Role '{role_id}' successfully removed.")


@router.post(
    "/{role_id}/permissions",
    response_model=RoleResponse,
    summary="Assign Permissions to Role",
    description="Binds a set of permissions to the specified role.",
)
async def assign_permissions_to_role(
    role_id: str,
    payload: AssignPermissionsRequest,
    tenant_id: str = Depends(get_tenant_id),
    current_user: User = Depends(require_permission("roles:assign")),
    db: AsyncSession = Depends(get_db),
):
    role_repo = RoleRepository(db)
    perm_repo = PermissionRepository(db)

    role = await role_repo.get_by_id(role_id, tenant_id=tenant_id)
    if not role:
        raise ResourceNotFoundError(f"Role '{role_id}' not found")

    perms = await perm_repo.get_by_names(payload.permission_names)
    await role_repo.set_permissions(role, perms)
    return serialize_role(role)


@router.get(
    "/users/{user_id}/roles",
    response_model=List[RoleResponse],
    summary="Get User Roles",
    description="Lists all roles assigned to a specific user.",
)
async def get_user_roles(
    user_id: str,
    tenant_id: str = Depends(get_tenant_id),
    current_user: User = Depends(require_permission("roles:read")),
    db: AsyncSession = Depends(get_db),
):
    user_repo = UserRepository(db)
    user = await user_repo.get_by_id(user_id, tenant_id=tenant_id)
    if not user:
        raise ResourceNotFoundError(f"User '{user_id}' not found")
    return [serialize_role(r) for r in user.roles]

