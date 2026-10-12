"""Refresh Token Repository (Layer 4).

Manages persistence, rotation verification, single-use invalidation,
and token family theft revocation for OAuth 2.0 refresh sessions.
"""

from datetime import datetime, timezone
from typing import Optional
from sqlalchemy import select, update, delete
from sqlalchemy.ext.asyncio import AsyncSession
from auth_service.models.token import RefreshToken


class TokenRepository:
    """Data access repository for RefreshToken records."""

    def __init__(self, session: AsyncSession):
        self.session = session

    async def create(
        self,
        user_id: str,
        tenant_id: str,
        token_hash: str,
        family_id: str,
        expires_at: datetime,
    ) -> RefreshToken:
        """Persist a new refresh token record."""
        token = RefreshToken(
            user_id=user_id,
            tenant_id=tenant_id,
            token_hash=token_hash,
            family_id=family_id,
            expires_at=expires_at,
            is_revoked=False,
        )
        self.session.add(token)
        await self.session.flush()
        return token

    async def get_by_hash(self, token_hash: str) -> Optional[RefreshToken]:
        """Lookup token by cryptographic SHA-256 hash."""
        res = await self.session.execute(
            select(RefreshToken).where(RefreshToken.token_hash == token_hash)
        )
        return res.scalar_one_or_none()

    async def revoke_token(self, token_id: str) -> None:
        """Mark an individual refresh token as revoked."""
        await self.session.execute(
            update(RefreshToken)
            .where(RefreshToken.id == token_id)
            .values(is_revoked=True)
        )
        await self.session.flush()

    async def revoke_family(self, family_id: str) -> int:
        """Revoke all tokens in a family upon detection of a reuse attack."""
        res = await self.session.execute(
            update(RefreshToken)
            .where(RefreshToken.family_id == family_id)
            .values(is_revoked=True)
        )
        await self.session.flush()
        return res.rowcount

    async def revoke_user_sessions(self, user_id: str) -> int:
        """Revoke all active refresh tokens belonging to a user (e.g. password reset/logout all)."""
        res = await self.session.execute(
            update(RefreshToken)
            .where(RefreshToken.user_id == user_id)
            .values(is_revoked=True)
        )
        await self.session.flush()
        return res.rowcount

    async def delete_expired(self) -> int:
        """Purge expired tokens from the database."""
        now = datetime.now(timezone.utc)
        res = await self.session.execute(
            delete(RefreshToken).where(RefreshToken.expires_at < now)
        )
        await self.session.flush()
        return res.rowcount
