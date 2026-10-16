"""Role Entity Model (Layer 4).

Represents named collections of permissions bound to tenant realms or system-wide scope.
"""

from sqlalchemy import Boolean, Column, ForeignKey, String, Text, UniqueConstraint
from sqlalchemy.orm import relationship
from auth_service.models.base import Base, UUIDPrimaryKeyMixin, TimestampMixin, ModelSerializerMixin
from auth_service.models.associations import role_permissions, user_roles


class Role(Base, UUIDPrimaryKeyMixin, TimestampMixin, ModelSerializerMixin):
    """Role definition entity."""

    __tablename__ = "roles"
    __table_args__ = (
        UniqueConstraint("tenant_id", "name", name="uq_tenant_role_name"),
    )

    tenant_id = Column(String(36), ForeignKey("tenants.id", ondelete="CASCADE"), nullable=False, index=True)
    name = Column(String(50), nullable=False, index=True)
    description = Column(Text, nullable=True)
    is_system = Column(Boolean, default=False, nullable=False)

    # Relationships
    tenant = relationship("Tenant", back_populates="roles")
    permissions = relationship("Permission", secondary=role_permissions, back_populates="roles", lazy="selectin")
    users = relationship("User", secondary=user_roles, back_populates="roles", lazy="selectin")

    def __repr__(self) -> str:
        return f"<Role id={self.id} name='{self.name}' tenant_id='{self.tenant_id}'>"
