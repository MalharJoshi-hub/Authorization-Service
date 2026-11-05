"""Webhook Subscriptions API Router (Layer 5: API).

Registers webhook receivers to broadcast real-time identity notifications to external backends.
"""

from datetime import datetime
from typing import List, Optional
from fastapi import APIRouter, Depends, status
from pydantic import BaseModel, Field, HttpUrl
from sqlalchemy.ext.asyncio import AsyncSession
from auth_service.core.dependencies import (
    get_current_active_user,
    get_db,
    get_tenant_id,
    require_permission,
)
from auth_service.models.user import User
from auth_service.services.webhook_service import webhook_service
from auth_service.api.schemas.common import MessageResponse


router = APIRouter(prefix="/webhooks", tags=["Webhooks & Event Fanout"])


class WebhookCreateRequest(BaseModel):
    url: str = Field(..., description="HTTPS destination URL")
    events: List[str] = Field(default_factory=lambda: ["*"], description="Subscribed event patterns")
    description: Optional[str] = None


class WebhookResponse(BaseModel):
    id: str
    tenant_id: str
    url: str
    secret: str
    description: Optional[str] = None
    subscribed_events: List[str]
    is_active: bool
    created_at: datetime


@router.get(
    "",
    response_model=List[WebhookResponse],
    summary="List Tenant Webhooks",
    description="Lists all webhook subscriptions registered for the tenant organization.",
)
async def list_webhooks(
    tenant_id: str = Depends(get_tenant_id),
    current_user: User = Depends(require_permission("tenants:update")),
    db: AsyncSession = Depends(get_db),
):
    endpoints = await webhook_service.list_endpoints(db, tenant_id)
    return [
        WebhookResponse(
            id=ep.id,
            tenant_id=ep.tenant_id,
            url=ep.url,
            secret=ep.secret,
            description=ep.description,
            subscribed_events=ep.subscribed_events,
            is_active=ep.is_active,
            created_at=ep.created_at,
        )
        for ep in endpoints
    ]


@router.post(
    "",
    response_model=WebhookResponse,
    status_code=status.HTTP_201_CREATED,
    summary="Register Webhook Endpoint",
    description="Registers an external destination URL with a generated signing secret.",
)
async def create_webhook(
    payload: WebhookCreateRequest,
    tenant_id: str = Depends(get_tenant_id),
    current_user: User = Depends(require_permission("tenants:update")),
    db: AsyncSession = Depends(get_db),
):
    ep = await webhook_service.register_endpoint(
        db=db,
        tenant_id=tenant_id,
        url=payload.url,
        events=payload.events,
        description=payload.description,
    )
    return WebhookResponse(
        id=ep.id,
        tenant_id=ep.tenant_id,
        url=ep.url,
        secret=ep.secret,
        description=ep.description,
        subscribed_events=ep.subscribed_events,
        is_active=ep.is_active,
        created_at=ep.created_at,
    )


@router.delete(
    "/{webhook_id}",
    response_model=MessageResponse,
    summary="Delete Webhook Subscription",
    description="Removes an existing webhook destination.",
)
async def delete_webhook(
    webhook_id: str,
    tenant_id: str = Depends(get_tenant_id),
    current_user: User = Depends(require_permission("tenants:update")),
    db: AsyncSession = Depends(get_db),
):
    await webhook_service.delete_endpoint(db, tenant_id, webhook_id)
    return MessageResponse(message=f"Webhook '{webhook_id}' successfully removed.")


@router.post(
    "/{webhook_id}/ping",
    response_model=MessageResponse,
    summary="Dispatch Test Ping Event",
    description="Triggers a mock event dispatch to verify webhook receiver connectivity.",
)
async def ping_webhook(
    webhook_id: str,
    tenant_id: str = Depends(get_tenant_id),
    current_user: User = Depends(require_permission("tenants:update")),
    db: AsyncSession = Depends(get_db),
):
    count = await webhook_service.dispatch_event(
        db, tenant_id, "ping", {"message": "Test ping event from Auth-as-a-Service"}
    )
    return MessageResponse(message=f"Dispatched test ping to {count} matching endpoints.")

