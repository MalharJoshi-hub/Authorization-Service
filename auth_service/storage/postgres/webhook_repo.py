"""Webhook Endpoint Repository (Layer 4).

CRUD data access for tenant webhook destinations and event subscription filters.
"""

from typing import List, Optional
from sqlalchemy import select, delete
from sqlalchemy.ext.asyncio import AsyncSession
from auth_service.models.webhook import WebhookEndpoint
from auth_service.core.exceptions import ResourceNotFoundError


class WebhookRepository:
    """Data access repository for WebhookEndpoint entity."""

    def __init__(self, session: AsyncSession):
        self.session = session

    async def create(
        self,
        tenant_id: str,
        url: str,
        secret: str,
        events: Optional[List[str]] = None,
        description: Optional[str] = None,
    ) -> WebhookEndpoint:
        """Register a new webhook destination."""
        endpoint = WebhookEndpoint(
            tenant_id=tenant_id,
            url=url.strip(),
            secret=secret,
            description=description,
            is_active=True,
        )
        endpoint.subscribed_events = events or ["*"]
        self.session.add(endpoint)
        await self.session.flush()
        return endpoint

    async def get_by_id(self, endpoint_id: str, tenant_id: Optional[str] = None) -> Optional[WebhookEndpoint]:
        """Fetch endpoint by ID."""
        stmt = select(WebhookEndpoint).where(WebhookEndpoint.id == endpoint_id)
        if tenant_id:
            stmt = stmt.where(WebhookEndpoint.tenant_id == tenant_id)
        res = await self.session.execute(stmt)
        return res.scalar_one_or_none()

    async def list_by_tenant(self, tenant_id: str) -> List[WebhookEndpoint]:
        """List all webhook endpoints for a tenant."""
        stmt = (
            select(WebhookEndpoint)
            .where(WebhookEndpoint.tenant_id == tenant_id)
            .order_by(WebhookEndpoint.created_at.desc())
        )
        res = await self.session.execute(stmt)
        return list(res.scalars().all())

    async def delete(self, endpoint_id: str, tenant_id: str) -> bool:
        """Delete webhook endpoint."""
        stmt = delete(WebhookEndpoint).where(
            WebhookEndpoint.id == endpoint_id, WebhookEndpoint.tenant_id == tenant_id
        )
        res = await self.session.execute(stmt)
        await self.session.flush()
        if res.rowcount == 0:
            raise ResourceNotFoundError(f"Webhook '{endpoint_id}' not found")
        return True
