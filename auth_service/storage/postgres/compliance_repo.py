"""Compliance and Data Retention Repository.

Handles PostgreSQL persistence for data governance, retention policy sweeps,
and privacy audit trail management.
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List, Optional

from sqlalchemy import delete, func, select, update
from sqlalchemy.ext.asyncio import AsyncSession

from auth_service.core.logger import get_logger
from auth_service.models.audit_log import AuditLog
from auth_service.models.session import Session
from auth_service.models.token import RefreshToken

logger = get_logger("auth_service.storage.compliance_repo")


class ComplianceRepository:
    """Repository managing compliance records and database lifecycle maintenance."""

    def __init__(self, session: AsyncSession) -> None:
        self.session = session

    async def get_audit_event_count(self, user_id: Optional[str] = None, tenant_id: Optional[str] = None) -> int:
        """Count audit records matching optional filters."""
        query = select(func.count(AuditLog.id))
        if user_id:
            query = query.where(AuditLog.user_id == user_id)
        if tenant_id:
            query = query.where(AuditLog.tenant_id == tenant_id)
        res = await self.session.execute(query)
        return res.scalar_one()

    async def purge_expired_sessions(self, older_than_days: int = 30) -> int:
        """Remove inactive and expired sessions exceeding retention policy."""
        cutoff = datetime.now(timezone.utc) - timedelta(days=older_than_days)
        stmt = delete(Session).where((Session.expires_at < cutoff) | ((Session.is_active.is_(False)) & (Session.created_at < cutoff)))
        res = await self.session.execute(stmt)
        await self.session.commit()
        deleted = res.rowcount or 0
        logger.info("Purged %s expired sessions older than %s days", deleted, older_than_days)
        return deleted

    async def purge_revoked_tokens(self, older_than_days: int = 14) -> int:
        """Purge revoked refresh tokens past the retention window."""
        cutoff = datetime.now(timezone.utc) - timedelta(days=older_than_days)
        stmt = delete(RefreshToken).where((RefreshToken.is_revoked.is_(True)) & (RefreshToken.created_at < cutoff))
        res = await self.session.execute(stmt)
        await self.session.commit()
        deleted = res.rowcount or 0
        logger.info("Purged %s revoked tokens older than %s days", deleted, older_than_days)
        return deleted

    async def get_retention_summary(self) -> Dict[str, Any]:
        """Generate high-level database retention statistics for compliance reporting."""
        session_count_query = select(func.count(Session.id))
        session_count = (await self.session.execute(session_count_query)).scalar_one()

        audit_count_query = select(func.count(AuditLog.id))
        audit_count = (await self.session.execute(audit_count_query)).scalar_one()

        token_count_query = select(func.count(RefreshToken.id))
        token_count = (await self.session.execute(token_count_query)).scalar_one()

        return {
            "total_audit_events": audit_count,
            "total_sessions": session_count,
            "total_refresh_tokens": token_count,
            "generated_at": datetime.now(timezone.utc).isoformat(),
        }

