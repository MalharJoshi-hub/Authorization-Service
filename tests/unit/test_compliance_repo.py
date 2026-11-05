"""Unit tests for compliance repository and retention purge methods."""

import pytest
from auth_service.storage.postgres.compliance_repo import ComplianceRepository


@pytest.mark.asyncio
async def test_compliance_repo_counts_and_summary(db_session):
    repo = ComplianceRepository(session=db_session)

    count = await repo.get_audit_event_count()
    assert count >= 0

    summary = await repo.get_retention_summary()
    assert "total_audit_events" in summary
    assert "total_sessions" in summary
    assert "total_refresh_tokens" in summary


@pytest.mark.asyncio
async def test_purge_sessions_and_tokens(db_session):
    repo = ComplianceRepository(session=db_session)

    purged_sessions = await repo.purge_expired_sessions(older_than_days=30)
    assert purged_sessions >= 0

    purged_tokens = await repo.purge_revoked_tokens(older_than_days=14)
    assert purged_tokens >= 0

