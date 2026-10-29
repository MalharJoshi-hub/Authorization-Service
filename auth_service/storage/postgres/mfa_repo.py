"""MFA Repository (Layer 4).

Manages persistence of user TOTP secrets, activation timestamps, and backup recovery codes.
"""

from datetime import datetime, timezone
from typing import List, Optional
from sqlalchemy import select, delete
from sqlalchemy.ext.asyncio import AsyncSession
from auth_service.models.mfa import UserMFA
from auth_service.core.exceptions import ResourceNotFoundError


class MFARepository:
    """Data access repository for UserMFA entity."""

    def __init__(self, session: AsyncSession):
        self.session = session

    async def get_by_user_id(self, user_id: str) -> Optional[UserMFA]:
        """Lookup MFA profile by user identifier."""
        stmt = select(UserMFA).where(UserMFA.user_id == user_id)
        res = await self.session.execute(stmt)
        return res.scalar_one_or_none()

    async def create_or_update_secret(self, user_id: str, secret: str) -> UserMFA:
        """Initialize or reset pending TOTP enrollment secret."""
        profile = await self.get_by_user_id(user_id)
        if not profile:
            profile = UserMFA(
                user_id=user_id,
                secret_key=secret,
                is_enabled=False,
            )
            self.session.add(profile)
        else:
            profile.secret_key = secret
            profile.is_enabled = False
            profile.confirmed_at = None

        await self.session.flush()
        return profile

    async def activate_mfa(self, user_id: str, backup_code_hashes: List[str]) -> UserMFA:
        """Mark MFA as active and record hashed backup recovery codes."""
        profile = await self.get_by_user_id(user_id)
        if not profile:
            raise ResourceNotFoundError("MFA profile not found for user")

        profile.is_enabled = True
        profile.backup_codes = backup_code_hashes
        profile.confirmed_at = datetime.now(timezone.utc)
        await self.session.flush()
        return profile

    async def disable_mfa(self, user_id: str) -> bool:
        """Deactivate MFA on user account."""
        profile = await self.get_by_user_id(user_id)
        if profile:
            profile.is_enabled = False
            profile.backup_codes = []
            await self.session.flush()
        return True
