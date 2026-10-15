"""Role Repository (Layer 4).

Handles role lifecycle, permissions associations, and tenant boundary enforcement.
"""

from typing import List, Optional
from sqlalchemy import select, func, delete
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload
from auth_service.models.role import Role
from auth_service.models.permission import Permission
from auth_service.core.exceptions import ConflictError, ResourceNotFoundError, ValidationError


class RoleRepository:
    """Data access repository for Role entities."""

    def __init__(self, session: AsyncSession):
        self.session = session

    async def create(
        self,
        tenant_id: str,
        name: str,
        description: Optional[str] = None,
        is_system: bool = False,
        permissions: Optional[List[Permission]] = None,
    ) -> Role:
        """Create a new role for a tenant."""
        norm_name = name.strip().lower()
        existing = await self.get_by_name(tenant_id, norm_name)
        if existing:
            raise ConflictError(f"Role '{norm_name}' already exists in this tenant")

        role = Role(
            tenant_id=tenant_id,
            name=norm_name,
            description=description,
            is_system=is_system,
        )
        if permissions:
            role.permissions = permissions

        self.session.add(role)
        await self.session.flush()
        return role

    async def get_by_id(self, role_id: str, tenant_id: Optional[str] = None) -> Optional[Role]:
        """Fetch role by ID with loaded permissions."""
        stmt = select(Role).options(selectinload(Role.permissions)).where(Role.id == role_id)
        if tenant_id:
            stmt = stmt.where(Role.tenant_id == tenant_id)
        res = await self.session.execute(stmt)
        return res.scalar_one_or_none()

    async def get_by_name(self, tenant_id: str, name: str) -> Optional[Role]:
        """Fetch role by normalized name within a tenant."""
        stmt = (
            select(Role)
            .options(selectinload(Role.permissions))
            .where(Role.tenant_id == tenant_id, Role.name == name.strip().lower())
        )
        res = await self.session.execute(stmt)
        return res.scalar_one_or_none()

    async def list_roles(self, tenant_id: str) -> List[Role]:
        """List all roles belonging to a tenant."""
        stmt = (
            select(Role)
            .options(selectinload(Role.permissions))
            .where(Role.tenant_id == tenant_id)
            .order_by(Role.is_system.desc(), Role.name.asc())
        )
        res = await self.session.execute(stmt)
        return list(res.scalars().all())

    async def update(
        self,
        role_id: str,
        tenant_id: str,
        name: Optional[str] = None,
        description: Optional[str] = None,
    ) -> Role:
        """Update role metadata."""
        role = await self.get_by_id(role_id, tenant_id=tenant_id)
        if not role:
            raise ResourceNotFoundError(f"Role '{role_id}' not found")

        if role.is_system and name and name != role.name:
            raise ValidationError("Cannot rename a protected system role")

        if name:
            norm = name.strip().lower()
            if norm != role.name:
                clash = await self.get_by_name(tenant_id, norm)
                if clash:
                    raise ConflictError(f"Role '{norm}' already exists")
                role.name = norm

        if description is not None:
            role.description = description

        await self.session.flush()
        return role

    async def delete(self, role_id: str, tenant_id: str) -> bool:
        """Delete custom role (system roles cannot be deleted)."""
        role = await self.get_by_id(role_id, tenant_id=tenant_id)
        if not role:
            raise ResourceNotFoundError(f"Role '{role_id}' not found")
        if role.is_system:
            raise ValidationError("Protected system roles cannot be deleted")

        await self.session.delete(role)
        await self.session.flush()
        return True

    async def assign_permission(self, role: Any, permission: Any) -> None:
        """Assign permission to role, accepting instances or IDs."""
        role_obj = role
        if isinstance(role, (str, bytes)) or hasattr(role, "hex"):
            role_obj = await self.get_by_id(str(role))
            if not role_obj:
                raise ResourceNotFoundError(f"Role '{role}' not found")

        perm_obj = permission
        if isinstance(permission, (str, bytes)) or hasattr(permission, "hex"):
            stmt = select(Permission).where(Permission.id == str(permission))
            res = await self.session.execute(stmt)
            perm_obj = res.scalar_one_or_none()
            if not perm_obj:
                raise ResourceNotFoundError(f"Permission '{permission}' not found")

        if perm_obj not in role_obj.permissions:
            role_obj.permissions.append(perm_obj)
            await self.session.flush()

    async def set_permissions(self, role: Role, permissions: List[Permission]) -> None:
        """Replace role permissions with new set."""
        role.permissions = permissions
        await self.session.flush()
