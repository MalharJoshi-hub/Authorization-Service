"""Audit Log Model for Compliance and Security Auditing (Layer 4).

Represents an append-only immutable security ledger capturing all authentication,
credential updates, authorization mutations, and security events.
"""

from datetime import datetime, timezone
import json
from typing import Any, Dict, Optional
from sqlalchemy import Column, DateTime, ForeignKey, Index, String, Text
from auth_service.models.base import Base, UUIDPrimaryKeyMixin, ModelSerializerMixin


class AuditLog(Base, UUIDPrimaryKeyMixin, ModelSerializerMixin):
    """Immutable audit trail record."""

    __tablename__ = "audit_logs"
    __table_args__ = (
        Index("ix_audit_logs_tenant_created", "tenant_id", "created_at"),
        Index("ix_audit_logs_user_created", "user_id", "created_at"),
    )

    tenant_id = Column(String(36), nullable=False, index=True)
    user_id = Column(String(36), nullable=True, index=True)
    event_type = Column(String(50), nullable=False, index=True)
    ip_address = Column(String(45), nullable=True)
    user_agent = Column(String(512), nullable=True)
    status = Column(String(20), default="success", nullable=False)
    details_json = Column(Text, default="{}", nullable=False)
    created_at = Column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc), nullable=False, index=True)

    @property
    def action(self) -> str:
        """Alias for event_type."""
        return self.event_type

    @action.setter
    def action(self, val: str):
        self.event_type = val

    @property
    def details(self) -> Dict[str, Any]:
        """Deserialize audit details JSON."""
        try:
            return json.loads(self.details_json)
        except Exception:
            return {}

    @details.setter
    def details(self, val: Dict[str, Any]):
        """Serialize audit details dictionary to JSON."""
        self.details_json = json.dumps(val or {})

    def __repr__(self) -> str:
        return f"<AuditLog id={self.id} event='{self.event_type}' status='{self.status}'>"
