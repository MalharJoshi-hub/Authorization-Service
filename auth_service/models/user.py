"""User Identity Model (Layer 4).

Represents core user identity, credentials, verification state, and organization binding.
"""

from datetime import datetime
from sqlalchemy import Boolean, Column, DateTime, ForeignKey, String, UniqueConstraint
from sqlalchemy.orm import relationship
from auth_service.models.base import Base, UUIDPrimaryKeyMixin, TimestampMixin, ModelSerializerMixin
from auth_service.models.associations import user_roles


class User(Base, UUIDPrimaryKeyMixin, TimestampMixin, ModelSerializerMixin):
    """User account entity."""

    __tablename__ = "users"
    __table_args__ = (
        UniqueConstraint("tenant_id", "email", name="uq_tenant_user_email"),
    )

    tenant_id = Column(String(36), ForeignKey("tenants.id", ondelete="CASCADE"), nullable=False, index=True)
    email = Column(String(255), nullable=False, index=True)
    hashed_password = Column(String(255), nullable=True)  # Nullable for OAuth-only users
    full_name = Column(String(255), nullable=True)
    avatar_url = Column(String(1024), nullable=True)

    # Status Flags
    is_active = Column(Boolean, default=True, nullable=False, index=True)
    is_verified = Column(Boolean, default=False, nullable=False, index=True)
    is_superuser = Column(Boolean, default=False, nullable=False)

    last_login_at = Column(DateTime(timezone=True), nullable=True)

    # Relationships
    tenant = relationship("Tenant", back_populates="users")
    roles = relationship("Role", secondary=user_roles, back_populates="users", lazy="selectin")
    refresh_tokens = relationship("RefreshToken", back_populates="user", cascade="all, delete-orphan")
    api_keys = relationship("APIKey", back_populates="user", cascade="all, delete-orphan")
    oauth_accounts = relationship("OAuthAccount", back_populates="user", cascade="all, delete-orphan")

    @property
    def username(self) -> str:
        """Derive username from email handle."""
        return self.email.split("@")[0] if self.email else "user"

    def __repr__(self) -> str:
        return f"<User id={self.id} email='{self.email}' tenant_id='{self.tenant_id}'>"
