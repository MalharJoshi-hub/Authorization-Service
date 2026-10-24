"""Concurrent Device & Active Session Management Service (Layer 2 & Layer 4).

Tracks client device fingerprints, active login sessions, enforces concurrent session caps,
and provides remote session termination capabilities.
"""

import hashlib
from datetime import datetime, timezone, timedelta
from typing import List, Optional
from sqlalchemy import select, update, delete, func
from sqlalchemy.ext.asyncio import AsyncSession
from auth_service.models.session import UserSession
from auth_service.core.exceptions import ResourceNotFoundError


class SessionService:
    """Manages active device sessions per user."""

    def __init__(self, db: Optional[AsyncSession] = None):
        self.db = db

    @staticmethod
    def compute_device_fingerprint(user_agent: Optional[str], ip_address: Optional[str]) -> str:
        """Derive deterministic fingerprint from client agent and subnet."""
        raw = f"{user_agent or 'unknown'}|{ip_address or '127.0.0.1'}"
        return hashlib.sha256(raw.encode("utf-8")).hexdigest()

    @staticmethod
    def parse_device_name(user_agent: Optional[str]) -> str:
        """Extract human-readable device/browser label from user agent string."""
        if not user_agent:
            return "Unknown Device"
        ua = user_agent.lower()
        if "iphone" in ua or "ipad" in ua:
            return "iOS Device"
        if "android" in ua:
            return "Android Device"
        if "macintosh" in ua:
            return "macOS Browser"
        if "windows" in ua:
            return "Windows Browser"
        if "linux" in ua:
            return "Linux Browser"
        return "Web Browser"

    async def create_session(
        self,
        db_or_user_id: Any = None,
        user_id: Optional[str] = None,
        tenant_id: Optional[str] = None,
        user_agent: Optional[str] = None,
        ip_address: Optional[str] = None,
        device_fingerprint: Optional[str] = None,
        device_name: Optional[str] = None,
        days_valid: int = 14,
        max_concurrent_sessions: int = 5,
        **kwargs,
    ) -> UserSession:
        """Register active device session and enforce concurrent session limit."""
        db = self.db
        if isinstance(db_or_user_id, AsyncSession):
            db = db_or_user_id
        elif isinstance(db_or_user_id, str):
            user_id = db_or_user_id

        user_id = user_id or kwargs.get("user_id")
        tenant_id = tenant_id or kwargs.get("tenant_id")
        user_agent = user_agent or kwargs.get("user_agent")
        ip_address = ip_address or kwargs.get("ip_address")
        fingerprint = device_fingerprint or kwargs.get("device_fingerprint") or self.compute_device_fingerprint(user_agent, ip_address)
        dev_name = device_name or kwargs.get("device_name") or self.parse_device_name(user_agent)
        now = datetime.now(timezone.utc)
        expires_at = kwargs.get("expires_at") or (now + timedelta(days=days_valid))

        # 1. Enforce max concurrent sessions (terminate oldest active if limit reached)
        active_sessions = await self.list_active_sessions(db, user_id)
        if len(active_sessions) >= max_concurrent_sessions:
            to_terminate = active_sessions[max_concurrent_sessions - 1 :]
            for s in to_terminate:
                s.is_active = False

        # 2. Create fresh session
        user_session = UserSession(
            user_id=user_id,
            tenant_id=tenant_id,
            device_name=dev_name,
            device_fingerprint=fingerprint,
            ip_address=ip_address,
            user_agent=user_agent,
            is_active=True,
            last_seen_at=now,
            created_at=now,
            expires_at=expires_at,
        )
        db.add(user_session)
        await db.flush()
        return user_session

    async def get_active_sessions(self, user_id: str, db: Optional[AsyncSession] = None) -> List[UserSession]:
        """Convenience method to retrieve active user sessions."""
        session_db = db or self.db
        return await self.list_active_sessions(session_db, user_id)

    async def revoke_session(self, session_id: str, user_id: str, db: Optional[AsyncSession] = None) -> bool:
        """Convenience method to terminate a session."""
        session_db = db or self.db
        return await self.terminate_session(session_db, session_id, user_id)

    async def list_active_sessions(self, db: AsyncSession, user_id: str) -> List[UserSession]:
        """Fetch all active sessions for a user ordered by last activity."""
        now = datetime.now(timezone.utc)
        stmt = (
            select(UserSession)
            .where(
                UserSession.user_id == user_id,
                UserSession.is_active == True,
                UserSession.expires_at > now,
            )
            .order_by(UserSession.last_seen_at.desc())
        )
        res = await db.execute(stmt)
        return list(res.scalars().all())

    async def terminate_session(self, db: AsyncSession, session_id: str, user_id: str) -> bool:
        """Deactivate a specific session."""
        stmt = (
            update(UserSession)
            .where(UserSession.id == session_id, UserSession.user_id == user_id)
            .values(is_active=False)
        )
        res = await db.execute(stmt)
        await db.flush()
        if res.rowcount == 0:
            raise ResourceNotFoundError("Session not found")
        return True

    async def terminate_all_except(
        self, db: AsyncSession, user_id: str, current_session_id: Optional[str] = None
    ) -> int:
        """Deactivate all sessions for a user, optionally preserving current device session."""
        stmt = (
            update(UserSession)
            .where(UserSession.user_id == user_id, UserSession.is_active == True)
        )
        if current_session_id:
            stmt = stmt.where(UserSession.id != current_session_id)
        stmt = stmt.values(is_active=False)
        res = await db.execute(stmt)
        await db.flush()
        return res.rowcount


session_service = SessionService()
