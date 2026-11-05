"""Permission Entity Model (Layer 4).

Represents granular authorization capabilities structured as '<resource>:<action>'.
"""

from datetime import datetime, timezone
from sqlalchemy import Column, DateTime, String, Text
from sqlalchemy.orm import relationship
from auth_service.models.base import Base, UUIDPrimaryKeyMixin, ModelSerializerMixin
from auth_service.models.associations import role_permissions


class Permission(Base, UUIDPrimaryKeyMixin, ModelSerializerMixin):
    """Granular permission grant item."""

    __tablename__ = "permissions"

    name = Column(String(100), unique=True, nullable=False, index=True)
    resource = Column(String(50), nullable=False, index=True)
    action = Column(String(50), nullable=False)
    description = Column(Text, nullable=True)
    created_at = Column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc), nullable=False)

    # Relationships
    roles = relationship("Role", secondary=role_permissions, back_populates="permissions")

    def __repr__(self) -> str:
        return f"<Permission name='{self.name}'>"

