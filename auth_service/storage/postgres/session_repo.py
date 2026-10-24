"""User Session Repository (Layer 4).

Persists and queries active browser logins, client fingerprints, and expired session purges.
"""

from datetime import datetime, timezone, timedelta
from typing import List, Optional
from sqlalchemy import select, update, delete
from sqlalchemy.ext.asyncio import AsyncSession
from auth_service.models.session import UserSession
from auth_service.core.exceptions import ResourceNotFoundError


class SessionRepository:
    """Data access repository for UserSession entity."""

    def __init__(self, session: AsyncSession):
        self.session = session

    async def create(
        self,
        user_id: str,
        tenant_id: Optional[str] = None,
        device_name: Optional[str] = None,
        device_fingerprint: Optional[str] = None,
        ip_address: Optional[str] = None,
        user_agent: Optional[str] = None,
        expires_at: Optional[datetime] = None,
        **kwargs,
    ) -> UserSession:
        """Create and persist a new user session."""
        now = datetime.now(timezone.utc)
        sess = UserSession(
            user_id=user_id,
            tenant_id=tenant_id or "00000000-0000-0000-0000-000000000001",
            device_name=device_name or "Unknown Device",
            device_fingerprint=device_fingerprint or "default_fp",
            ip_address=ip_address or "127.0.0.1",
            user_agent=user_agent,
            is_active=True,
            last_seen_at=now,
            created_at=now,
            expires_at=expires_at or (now + timedelta(days=14)),
        )
        self.session.add(sess)
        await self.session.flush()
        return sess

    async def list_active_by_user(self, user_id: str) -> List[UserSession]:
        """Fetch all active sessions for a user."""
        return await self.list_user_sessions(user_id=user_id, active_only=True)

    async def deactivate(self, session_id: str, user_id: Optional[str] = None) -> bool:
        """Deactivate a session by ID."""
        stmt = update(UserSession).where(UserSession.id == session_id)
        if user_id:
            stmt = stmt.where(UserSession.user_id == user_id)
        stmt = stmt.values(is_active=False)
        res = await self.session.execute(stmt)
        await self.session.flush()
        return res.rowcount > 0

    async def get_by_id(self, session_id: str) -> Optional[UserSession]:
        """Fetch session by UUID."""
        stmt = select(UserSession).where(UserSession.id == session_id)
        res = await self.session.execute(stmt)
        return res.scalar_one_or_none()

    async def list_user_sessions(
        self, user_id: str, active_only: bool = True
    ) -> List[UserSession]:
        """Fetch sessions belonging to a user."""
        stmt = select(UserSession).where(UserSession.user_id == user_id)
        if active_only:
            now = datetime.now(timezone.utc)
            stmt = stmt.where(UserSession.is_active == True, UserSession.expires_at > now)
        stmt = stmt.order_by(UserSession.last_seen_at.desc())
        res = await self.session.execute(stmt)
        return list(res.scalars().all())

    async def update_last_seen(self, session_id: str) -> None:
        """Touch last_seen_at timestamp on active session."""
        await self.session.execute(
            update(UserSession)
            .where(UserSession.id == session_id)
            .values(last_seen_at=datetime.now(timezone.utc))
        )
        await self.session.flush()

    async def deactivate_session(self, session_id: str, user_id: str) -> bool:
        """Mark specific session as inactive."""
        stmt = (
            update(UserSession)
            .where(UserSession.id == session_id, UserSession.user_id == user_id)
            .values(is_active=False)
        )
        res = await self.session.execute(stmt)
        await self.session.flush()
        if res.rowcount == 0:
            raise ResourceNotFoundError(f"Session '{session_id}' not found")
        return True

    async def purge_expired(self) -> int:
        """Delete obsolete expired sessions from the database."""
        now = datetime.now(timezone.utc)
        stmt = delete(UserSession).where(UserSession.expires_at < now)
        res = await self.session.execute(stmt)
        await self.session.flush()
        return res.rowcount
