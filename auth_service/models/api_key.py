"""API Key Entity Model (Layer 4).

Represents machine-to-machine authentication credentials, scope definitions,
usage metadata, and expiration lifecycles.
"""

from datetime import datetime, timezone
import json
from typing import List
from sqlalchemy import Boolean, Column, DateTime, ForeignKey, String, Text
from sqlalchemy.orm import relationship
from auth_service.models.base import Base, UUIDPrimaryKeyMixin, ModelSerializerMixin


class APIKey(Base, UUIDPrimaryKeyMixin, ModelSerializerMixin):
    """Machine-to-Machine API credential."""

    __tablename__ = "api_keys"

    tenant_id = Column(String(36), ForeignKey("tenants.id", ondelete="CASCADE"), nullable=False, index=True)
    user_id = Column(String(36), ForeignKey("users.id", ondelete="CASCADE"), nullable=True, index=True)
    name = Column(String(100), nullable=False)
    prefix = Column(String(16), nullable=False, index=True)
    key_hash = Column(String(64), unique=True, nullable=False, index=True)
    scopes_json = Column(Text, default="[]", nullable=False)
    is_active = Column(Boolean, default=True, nullable=False, index=True)
    expires_at = Column(DateTime(timezone=True), nullable=True)
    last_used_at = Column(DateTime(timezone=True), nullable=True)
    created_at = Column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc), nullable=False)

    # Relationships
    tenant = relationship("Tenant", back_populates="api_keys")
    user = relationship("User", back_populates="api_keys")

    @property
    def scopes(self) -> List[str]:
        """Deserialize stored scopes JSON to list of strings."""
        try:
            return json.loads(self.scopes_json)
        except Exception:
            return []

    @scopes.setter
    def scopes(self, val: List[str]):
        """Serialize scopes list to JSON string."""
        self.scopes_json = json.dumps(val or [])

    def __repr__(self) -> str:
        return f"<APIKey id={self.id} prefix='{self.prefix}' tenant_id='{self.tenant_id}'>"
