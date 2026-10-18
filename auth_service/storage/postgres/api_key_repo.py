"""API Key Repository (Layer 4).

Manages storage, prefix lookups, hash validation, and revocation of machine credentials.
"""

from datetime import datetime, timezone
from typing import List, Optional
from sqlalchemy import select, update, delete
from sqlalchemy.ext.asyncio import AsyncSession
from auth_service.models.api_key import APIKey
from auth_service.core.exceptions import ResourceNotFoundError


class APIKeyRepository:
    """Data access repository for APIKey entities."""

    def __init__(self, session: AsyncSession):
        self.session = session

    async def create(
        self,
        tenant_id: str,
        name: str,
        prefix: str,
        key_hash: str,
        scopes: List[str],
        user_id: Optional[str] = None,
        expires_at: Optional[datetime] = None,
    ) -> APIKey:
        """Create and persist an API key record."""
        key = APIKey(
            tenant_id=tenant_id,
            user_id=user_id,
            name=name,
            prefix=prefix,
            key_hash=key_hash,
            expires_at=expires_at,
            is_active=True,
        )
        key.scopes = scopes
        self.session.add(key)
        await self.session.flush()
        return key

    async def get_by_id(self, key_id: str, tenant_id: Optional[str] = None) -> Optional[APIKey]:
        """Fetch API key by ID."""
        stmt = select(APIKey).where(APIKey.id == key_id)
        if tenant_id:
            stmt = stmt.where(APIKey.tenant_id == tenant_id)
        res = await self.session.execute(stmt)
        return res.scalar_one_or_none()

    async def get_by_hash(self, key_hash: str) -> Optional[APIKey]:
        """Lookup active API key by SHA-256 hash."""
        stmt = select(APIKey).where(APIKey.key_hash == key_hash, APIKey.is_active == True)
        res = await self.session.execute(stmt)
        return res.scalar_one_or_none()

    get_by_key_hash = get_by_hash

    async def list_keys(
        self,
        tenant_id: str,
        user_id: Optional[str] = None,
    ) -> List[APIKey]:
        """List API keys for tenant or specific user."""
        stmt = select(APIKey).where(APIKey.tenant_id == tenant_id)
        if user_id:
            stmt = stmt.where(APIKey.user_id == user_id)
        stmt = stmt.order_by(APIKey.created_at.desc())
        res = await self.session.execute(stmt)
        return list(res.scalars().all())

    async def update_last_used(self, key_id: str) -> None:
        """Record last used timestamp."""
        await self.session.execute(
            update(APIKey)
            .where(APIKey.id == key_id)
            .values(last_used_at=datetime.now(timezone.utc))
        )
        await self.session.flush()

    async def revoke(self, key_id: str, tenant_id: Optional[str] = None) -> APIKey:
        """Revoke / deactivate an API key."""
        key = await self.get_by_id(key_id, tenant_id=tenant_id)
        if not key:
            raise ResourceNotFoundError(f"API Key '{key_id}' not found")
        key.is_active = False
        await self.session.flush()
        return key
