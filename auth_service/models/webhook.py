"""Webhook Subscription Entity Model (Layer 4).

Represents external destination endpoints receiving cryptographic notifications of
identity events (e.g. user.created, user.verified, password.reset, account.locked).
"""

import json
from typing import List
from sqlalchemy import Boolean, Column, ForeignKey, String, Text
from auth_service.models.base import Base, UUIDPrimaryKeyMixin, TimestampMixin, ModelSerializerMixin


class WebhookEndpoint(Base, UUIDPrimaryKeyMixin, TimestampMixin, ModelSerializerMixin):
    """Destination webhook endpoint."""

    __tablename__ = "webhook_endpoints"

    tenant_id = Column(String(36), ForeignKey("tenants.id", ondelete="CASCADE"), nullable=False, index=True)
    url = Column(String(1024), nullable=False)
    secret = Column(String(64), nullable=False)
    description = Column(String(255), nullable=True)
    events_json = Column(Text, default='["*"]', nullable=False)
    is_active = Column(Boolean, default=True, nullable=False, index=True)

    @property
    def subscribed_events(self) -> List[str]:
        try:
            return json.loads(self.events_json)
        except Exception:
            return []

    @subscribed_events.setter
    def subscribed_events(self, val: List[str]):
        self.events_json = json.dumps(val or [])

    def __repr__(self) -> str:
        return f"<WebhookEndpoint id={self.id} url='{self.url}' active={self.is_active}>"


WebhookSubscription = WebhookEndpoint

