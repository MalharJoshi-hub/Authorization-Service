"""Permission Repository (Layer 4).

Handles querying, registration, and discovery of system permissions.
"""

from typing import List, Optional
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession
from auth_service.models.permission import Permission
from auth_service.core.exceptions import ConflictError, ResourceNotFoundError


class PermissionRepository:
    """Data access repository for Permission entities."""

    def __init__(self, session: AsyncSession):
        self.session = session

    async def create(
        self,
        name: str,
        resource: str,
        action: str,
        description: Optional[str] = None,
    ) -> Permission:
        """Create a new permission grant."""
        norm_name = name.strip().lower()
        existing = await self.get_by_name(norm_name)
        if existing:
            raise ConflictError(f"Permission '{norm_name}' already exists")

        perm = Permission(
            name=norm_name,
            resource=resource.strip().lower(),
            action=action.strip().lower(),
            description=description,
        )
        self.session.add(perm)
        await self.session.flush()
        return perm

    async def get_by_id(self, perm_id: str) -> Optional[Permission]:
        """Fetch permission by ID."""
        res = await self.session.execute(select(Permission).where(Permission.id == perm_id))
        return res.scalar_one_or_none()

    async def get_by_name(self, name: str) -> Optional[Permission]:
        """Fetch permission by unique canonical name."""
        res = await self.session.execute(
            select(Permission).where(Permission.name == name.strip().lower())
        )
        return res.scalar_one_or_none()

    async def get_by_names(self, names: List[str]) -> List[Permission]:
        """Fetch list of permissions matching given canonical names."""
        norm_names = [n.strip().lower() for n in names]
        res = await self.session.execute(
            select(Permission).where(Permission.name.in_(norm_names))
        )
        return list(res.scalars().all())

    async def list_permissions(self) -> List[Permission]:
        """List all system and custom permissions."""
        res = await self.session.execute(
            select(Permission).order_by(Permission.resource.asc(), Permission.action.asc())
        )
        return list(res.scalars().all())

