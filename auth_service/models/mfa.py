"""Multi-Factor Authentication (MFA/TOTP) Model (Layer 4).

Stores RFC 6238 Time-based One-Time Password (TOTP) configuration,
encrypted shared secrets, and hashed emergency recovery codes.
"""

from datetime import datetime, timezone
import json
from typing import List
from sqlalchemy import Boolean, Column, DateTime, ForeignKey, String, Text
from sqlalchemy.orm import relationship
from auth_service.models.base import Base, UUIDPrimaryKeyMixin, TimestampMixin, ModelSerializerMixin


class UserMFA(Base, UUIDPrimaryKeyMixin, TimestampMixin, ModelSerializerMixin):
    """MFA security profile for a user account."""

    __tablename__ = "user_mfa"

    user_id = Column(String(36), ForeignKey("users.id", ondelete="CASCADE"), unique=True, nullable=False, index=True)
    is_enabled = Column(Boolean, default=False, nullable=False, index=True)
    secret_key = Column(String(128), nullable=False)
    backup_codes_json = Column(Text, default="[]", nullable=False)
    confirmed_at = Column(DateTime(timezone=True), nullable=True)

    @property
    def backup_codes(self) -> List[str]:
        """Deserialize stored hashed backup recovery codes."""
        try:
            return json.loads(self.backup_codes_json)
        except Exception:
            return []

    @backup_codes.setter
    def backup_codes(self, val: List[str]):
        """Serialize backup codes list."""
        self.backup_codes_json = json.dumps(val or [])

    def __repr__(self) -> str:
        return f"<UserMFA user_id='{self.user_id}' enabled={self.is_enabled}>"
