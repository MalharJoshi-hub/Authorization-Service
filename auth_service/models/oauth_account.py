"""OAuth Social Account Model (Layer 4).

Represents linked third-party social provider identities (Google, GitHub).
"""

from datetime import datetime, timezone
import json
from typing import Any, Dict, Optional
from sqlalchemy import Column, ForeignKey, String, Text, UniqueConstraint
from sqlalchemy.orm import relationship
from auth_service.models.base import Base, UUIDPrimaryKeyMixin, TimestampMixin, ModelSerializerMixin


class OAuthAccount(Base, UUIDPrimaryKeyMixin, TimestampMixin, ModelSerializerMixin):
    """External social login provider linkage."""

    __tablename__ = "oauth_accounts"
    __table_args__ = (
        UniqueConstraint("provider", "provider_user_id", name="uq_provider_user_id"),
    )

    user_id = Column(String(36), ForeignKey("users.id", ondelete="CASCADE"), nullable=False, index=True)
    provider = Column(String(50), nullable=False, index=True)  # 'google', 'github'
    provider_user_id = Column(String(255), nullable=False, index=True)
    email = Column(String(255), nullable=True)
    access_token = Column(Text, nullable=True)
    refresh_token = Column(Text, nullable=True)
    profile_data_json = Column(Text, default="{}", nullable=False)

    # Relationships
    user = relationship("User", back_populates="oauth_accounts")

    @property
    def profile_data(self) -> Dict[str, Any]:
        try:
            return json.loads(self.profile_data_json)
        except Exception:
            return {}

    @profile_data.setter
    def profile_data(self, val: Dict[str, Any]):
        self.profile_data_json = json.dumps(val or {})

    def __repr__(self) -> str:
        return f"<OAuthAccount provider='{self.provider}' provider_user_id='{self.provider_user_id}'>"

