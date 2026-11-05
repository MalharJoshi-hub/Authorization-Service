"""Refresh Token Model (Layer 4).

Stores cryptographic hash, token family association, revocation state, and expiration
for OAuth 2.0 refresh token rotation.
"""

from datetime import datetime, timezone
from sqlalchemy import Boolean, Column, DateTime, ForeignKey, String
from sqlalchemy.orm import relationship
from auth_service.models.base import Base, UUIDPrimaryKeyMixin, ModelSerializerMixin


class RefreshToken(Base, UUIDPrimaryKeyMixin, ModelSerializerMixin):
    """Persisted refresh token record."""

    __tablename__ = "refresh_tokens"

    user_id = Column(String(36), ForeignKey("users.id", ondelete="CASCADE"), nullable=False, index=True)
    tenant_id = Column(String(36), ForeignKey("tenants.id", ondelete="CASCADE"), nullable=False, index=True)
    token_hash = Column(String(64), unique=True, nullable=False, index=True)
    family_id = Column(String(36), nullable=False, index=True)
    is_revoked = Column(Boolean, default=False, nullable=False, index=True)
    expires_at = Column(DateTime(timezone=True), nullable=False, index=True)
    created_at = Column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc), nullable=False)

    # Relationships
    user = relationship("User", back_populates="refresh_tokens")

    def __repr__(self) -> str:
        return f"<RefreshToken id={self.id} user_id='{self.user_id}' family_id='{self.family_id}'>"

