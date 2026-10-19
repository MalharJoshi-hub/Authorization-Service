"""Tenant Repository (Layer 4).

Manages tenant organization provisioning, configuration updates, and isolation scopes.
"""

from typing import List, Optional
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession
from auth_service.models.tenant import Tenant
from auth_service.core.exceptions import ConflictError, ResourceNotFoundError


class TenantRepository:
    """Data access repository for Tenant entities."""

    def __init__(self, session: AsyncSession):
        self.session = session

    async def create(
        self,
        name: str,
        slug: str,
        plan: str = "standard",
        settings_json: str = "{}",
    ) -> Tenant:
        """Create a new tenant organization."""
        norm_slug = slug.strip().lower()
        existing = await self.get_by_slug(norm_slug)
        if existing:
            raise ConflictError(f"Tenant slug '{norm_slug}' is already taken")

        tenant = Tenant(
            name=name.strip(),
            slug=norm_slug,
            plan=plan,
            settings_json=settings_json,
            is_active=True,
        )
        self.session.add(tenant)
        await self.session.flush()
        return tenant

    async def get_by_id(self, tenant_id: str) -> Optional[Tenant]:
        """Fetch tenant by UUID."""
        res = await self.session.execute(select(Tenant).where(Tenant.id == tenant_id))
        return res.scalar_one_or_none()

    async def get_by_slug(self, slug: str) -> Optional[Tenant]:
        """Fetch tenant by unique subdomain or slug identifier."""
        res = await self.session.execute(
            select(Tenant).where(Tenant.slug == slug.strip().lower())
        )
        return res.scalar_one_or_none()

    async def list_tenants(self, skip: int = 0, limit: int = 50) -> List[Tenant]:
        """List active tenants."""
        res = await self.session.execute(
            select(Tenant).order_by(Tenant.created_at.desc()).offset(skip).limit(limit)
        )
        return list(res.scalars().all())

    async def update(
        self,
        tenant_id: str,
        name: Optional[str] = None,
        plan: Optional[str] = None,
        is_active: Optional[bool] = None,
        settings_json: Optional[str] = None,
    ) -> Tenant:
        """Update tenant parameters."""
        tenant = await self.get_by_id(tenant_id)
        if not tenant:
            raise ResourceNotFoundError(f"Tenant '{tenant_id}' not found")

        if name is not None:
            tenant.name = name.strip()
        if plan is not None:
            tenant.plan = plan
        if is_active is not None:
            tenant.is_active = is_active
        if settings_json is not None:
            tenant.settings_json = settings_json

        await self.session.flush()
        return tenant
