"""Webhook Event Notification & Fanout Service (Layer 3 & Layer 5).

Dispatches cryptographically signed HMAC SHA-256 webhooks to external subscriber systems
upon critical identity and security state changes.
"""

import hashlib
import hmac
import json
import secrets
import time
from typing import Any, Dict, List, Optional
import httpx
from sqlalchemy import select, delete
from sqlalchemy.ext.asyncio import AsyncSession
from auth_service.models.webhook import WebhookEndpoint
from auth_service.core.logger import logger
from auth_service.core.exceptions import ResourceNotFoundError


class WebhookService:
    """Manages webhook endpoint subscriptions and payload signing."""

    @staticmethod
    def generate_secret() -> str:
        """Generate high-entropy shared secret for webhook signing."""
        return secrets.token_hex(32)

    @staticmethod
    def generate_signature(payload: Any, secret: str) -> str:
        """Compute standard HMAC SHA-256 hexdigest."""
        if isinstance(payload, str):
            payload_bytes = payload.encode("utf-8")
        elif isinstance(payload, bytes):
            payload_bytes = payload
        else:
            payload_bytes = json.dumps(payload, default=str).encode("utf-8")
        return hmac.new(secret.encode("utf-8"), payload_bytes, hashlib.sha256).hexdigest()

    @staticmethod
    def compute_signature(payload_bytes: bytes, secret: str, timestamp: int) -> str:
        """Compute HMAC SHA-256 signature formatted as 't={timestamp},v1={hash}'."""
        signed_payload = f"{timestamp}.".encode("utf-8") + payload_bytes
        signature = hmac.new(
            secret.encode("utf-8"), signed_payload, hashlib.sha256
        ).hexdigest()
        return f"t={timestamp},v1={signature}"

    async def register_endpoint(
        self,
        db: AsyncSession,
        tenant_id: str,
        url: str,
        events: Optional[List[str]] = None,
        description: Optional[str] = None,
    ) -> WebhookEndpoint:
        """Create new webhook destination."""
        endpoint = WebhookEndpoint(
            tenant_id=tenant_id,
            url=url.strip(),
            secret=self.generate_secret(),
            description=description,
            is_active=True,
        )
        endpoint.subscribed_events = events or ["*"]
        db.add(endpoint)
        await db.flush()
        return endpoint

    async def list_endpoints(self, db: AsyncSession, tenant_id: str) -> List[WebhookEndpoint]:
        """List active webhooks for tenant."""
        stmt = select(WebhookEndpoint).where(WebhookEndpoint.tenant_id == tenant_id)
        res = await db.execute(stmt)
        return list(res.scalars().all())

    async def delete_endpoint(self, db: AsyncSession, tenant_id: str, endpoint_id: str) -> bool:
        """Remove a webhook subscription."""
        stmt = delete(WebhookEndpoint).where(
            WebhookEndpoint.id == endpoint_id, WebhookEndpoint.tenant_id == tenant_id
        )
        res = await db.execute(stmt)
        await db.flush()
        if res.rowcount == 0:
            raise ResourceNotFoundError("Webhook endpoint not found")
        return True

    async def dispatch_event(
        self,
        db: AsyncSession,
        tenant_id: str,
        event_type: str,
        data: Dict[str, Any],
    ) -> int:
        """Fan out signed event to all matching tenant webhooks."""
        endpoints = await self.list_endpoints(db, tenant_id)
        matching = [
            ep
            for ep in endpoints
            if ep.is_active and ("*" in ep.subscribed_events or event_type in ep.subscribed_events)
        ]

        if not matching:
            return 0

        timestamp = int(time.time())
        envelope = {
            "event": event_type,
            "tenant_id": tenant_id,
            "timestamp": timestamp,
            "data": data,
        }
        payload_bytes = json.dumps(envelope).encode("utf-8")
        dispatched_count = 0

        for ep in matching:
            sig = self.compute_signature(payload_bytes, ep.secret, timestamp)
            try:
                # Dispatch async POST
                async with httpx.AsyncClient(timeout=3.0) as client:
                    await client.post(
                        ep.url,
                        content=payload_bytes,
                        headers={
                            "Content-Type": "application/json",
                            "X-AaaS-Signature": sig,
                            "User-Agent": "AaaS-Webhook-Dispatcher/1.0",
                        },
                    )
                dispatched_count += 1
            except Exception as e:
                logger.warning(f"Webhook delivery failed for {ep.url}: {e}")

        return dispatched_count


webhook_service = WebhookService()
