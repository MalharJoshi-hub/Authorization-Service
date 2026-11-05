"""Tenant Entity Model for Multi-Tenant Isolation (Layer 4).

Represents organization boundaries, domains, settings, and subscription tier policies.
"""

from sqlalchemy import Boolean, Column, String, Text
from sqlalchemy.orm import relationship
from auth_service.models.base import Base, UUIDPrimaryKeyMixin, TimestampMixin, ModelSerializerMixin


class Tenant(Base, UUIDPrimaryKeyMixin, TimestampMixin, ModelSerializerMixin):
    """Tenant Organization Entity."""

    __tablename__ = "tenants"

    name = Column(String(255), nullable=False, index=True)
    slug = Column(String(100), unique=True, nullable=False, index=True)
    plan = Column(String(50), default="standard", nullable=False)
    is_active = Column(Boolean, default=True, nullable=False)
    settings_json = Column(Text, default="{}", nullable=False)

    # Relationships
    users = relationship("User", back_populates="tenant", cascade="all, delete-orphan")
    roles = relationship("Role", back_populates="tenant", cascade="all, delete-orphan")
    api_keys = relationship("APIKey", back_populates="tenant", cascade="all, delete-orphan")

    def __repr__(self) -> str:
        return f"<Tenant id={self.id} name='{self.name}' slug='{self.slug}'>"

