"""Audit Log Repository (Layer 4).

Appends immutable audit trail records, queries compliance logs, and exports CSV streams.
"""

import csv
import io
from datetime import datetime, timezone, timedelta
from typing import Any, Dict, List, Optional, Tuple
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession
from auth_service.models.audit_log import AuditLog


class AuditLogRepository:
    """Data access repository for AuditLog entries."""

    def __init__(self, session: AsyncSession):
        self.session = session

    async def log(
        self,
        tenant_id: str,
        event_type: str,
        user_id: Optional[str] = None,
        ip_address: Optional[str] = None,
        user_agent: Optional[str] = None,
        status: str = "success",
        details: Optional[Dict[str, Any]] = None,
    ) -> AuditLog:
        """Record an immutable audit log entry."""
        audit = AuditLog(
            tenant_id=tenant_id,
            user_id=user_id,
            event_type=event_type,
            ip_address=ip_address,
            user_agent=user_agent,
            status=status,
        )
        if details:
            audit.details = details

        self.session.add(audit)
        await self.session.flush()
        return audit

    record = log

    async def query(
        self,
        tenant_id: Optional[str] = None,
        user_id: Optional[str] = None,
        event_type: Optional[str] = None,
        status: Optional[str] = None,
        start_date: Optional[datetime] = None,
        end_date: Optional[datetime] = None,
        skip: int = 0,
        limit: int = 50,
    ) -> Tuple[List[AuditLog], int]:
        """Query paginated audit logs with flexible security filtering."""
        query = select(AuditLog)
        count_query = select(func.count(AuditLog.id))

        if tenant_id:
            query = query.where(AuditLog.tenant_id == tenant_id)
            count_query = count_query.where(AuditLog.tenant_id == tenant_id)

        if user_id:
            query = query.where(AuditLog.user_id == user_id)
            count_query = count_query.where(AuditLog.user_id == user_id)

        if event_type:
            query = query.where(AuditLog.event_type == event_type)
            count_query = count_query.where(AuditLog.event_type == event_type)

        if status:
            query = query.where(AuditLog.status == status)
            count_query = count_query.where(AuditLog.status == status)

        if start_date:
            query = query.where(AuditLog.created_at >= start_date)
            count_query = count_query.where(AuditLog.created_at >= start_date)

        if end_date:
            query = query.where(AuditLog.created_at <= end_date)
            count_query = count_query.where(AuditLog.created_at <= end_date)

        total_res = await self.session.execute(count_query)
        total = total_res.scalar() or 0

        query = query.order_by(AuditLog.created_at.desc()).offset(skip).limit(limit)
        res = await self.session.execute(query)
        logs = list(res.scalars().all())

        return logs, total

    list_logs = query

    async def export_csv(
        self,
        tenant_id: Optional[str] = None,
        event_type: Optional[str] = None,
        limit: int = 5000,
    ) -> str:
        """Export audit events as a formatted CSV string."""
        logs, _ = await self.query(tenant_id=tenant_id, event_type=event_type, limit=limit)
        output = io.StringIO()
        writer = csv.writer(output)
        writer.writerow(["ID", "Timestamp", "Tenant ID", "User ID", "Event Type", "Status", "IP Address", "User Agent", "Details"])

        for log in logs:
            writer.writerow([
                log.id,
                log.created_at.isoformat() if log.created_at else "",
                log.tenant_id,
                log.user_id or "",
                log.event_type,
                log.status,
                log.ip_address or "",
                log.user_agent or "",
                log.details_json,
            ])

        return output.getvalue()

    async def get_analytics_summary(self, tenant_id: Optional[str] = None, days: int = 7) -> Dict[str, Any]:
        """Compute aggregated security and authentication metrics over time."""
        cutoff = datetime.now(timezone.utc) - timedelta(days=days)

        base_filter = [AuditLog.created_at >= cutoff]
        if tenant_id:
            base_filter.append(AuditLog.tenant_id == tenant_id)

        # Total events
        total_res = await self.session.execute(
            select(func.count(AuditLog.id)).where(*base_filter)
        )
        total_events = total_res.scalar() or 0

        # Successful logins
        login_res = await self.session.execute(
            select(func.count(AuditLog.id)).where(
                *base_filter,
                AuditLog.event_type == "login",
                AuditLog.status == "success",
            )
        )
        successful_logins = login_res.scalar() or 0

        # Failed logins
        failed_res = await self.session.execute(
            select(func.count(AuditLog.id)).where(
                *base_filter,
                AuditLog.event_type == "login",
                AuditLog.status == "failed",
            )
        )
        failed_logins = failed_res.scalar() or 0

        # New registrations
        reg_res = await self.session.execute(
            select(func.count(AuditLog.id)).where(
                *base_filter,
                AuditLog.event_type == "register",
                AuditLog.status == "success",
            )
        )
        new_registrations = reg_res.scalar() or 0

        # Password resets
        reset_res = await self.session.execute(
            select(func.count(AuditLog.id)).where(
                *base_filter,
                AuditLog.event_type == "password_reset",
                AuditLog.status == "success",
            )
        )
        password_resets = reset_res.scalar() or 0

        return {
            "period_days": days,
            "total_events": total_events,
            "successful_logins": successful_logins,
            "failed_logins": failed_logins,
            "new_registrations": new_registrations,
            "password_resets": password_resets,
        }

    async def get_event_counts_by_type(self, tenant_id: Optional[str] = None, days: int = 7) -> List[Dict[str, Any]]:
        """Retrieve breakdown of event types within time range."""
        cutoff = datetime.now(timezone.utc) - timedelta(days=days)
        base_filter = [AuditLog.created_at >= cutoff]
        if tenant_id:
            base_filter.append(AuditLog.tenant_id == tenant_id)

        stmt = (
            select(AuditLog.event_type, func.count(AuditLog.id).label("count"))
            .where(*base_filter)
            .group_by(AuditLog.event_type)
            .order_by(func.count(AuditLog.id).desc())
        )
        res = await self.session.execute(stmt)
        return [{"event_type": row[0], "count": row[1]} for row in res.all()]
