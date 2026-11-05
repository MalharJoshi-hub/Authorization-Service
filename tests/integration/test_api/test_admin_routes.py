"""API Integration Tests for Administrative Dashboard & Observability (Phase 8)."""

import pytest
from httpx import AsyncClient
from auth_service.models.user import User


@pytest.mark.asyncio
async def test_admin_list_users(async_client: AsyncClient, admin_headers: dict, test_user: User):
    response = await async_client.get("/api/v1/admin/users", headers=admin_headers)
    assert response.status_code == 200
    data = response.json()
    assert data["total"] >= 1
    assert len(data["items"]) >= 1


@pytest.mark.asyncio
async def test_admin_lock_and_unlock_user(
    async_client: AsyncClient, admin_headers: dict, test_user: User
):
    # Lock user
    lock_resp = await async_client.post(
        f"/api/v1/admin/users/{test_user.id}/lock", headers=admin_headers
    )
    assert lock_resp.status_code == 200

    # Unlock user
    unlock_resp = await async_client.post(
        f"/api/v1/admin/users/{test_user.id}/unlock", headers=admin_headers
    )
    assert unlock_resp.status_code == 200


@pytest.mark.asyncio
async def test_admin_audit_logs_and_csv_export(
    async_client: AsyncClient, admin_headers: dict
):
    # Query audit logs
    query_resp = await async_client.get("/api/v1/admin/audit-logs", headers=admin_headers)
    assert query_resp.status_code == 200
    logs = query_resp.json()
    assert "total" in logs

    # CSV Export
    csv_resp = await async_client.get("/api/v1/admin/audit-logs/export", headers=admin_headers)
    assert csv_resp.status_code == 200
    assert "text/csv" in csv_resp.headers["content-type"]
    assert "Timestamp" in csv_resp.text


@pytest.mark.asyncio
async def test_admin_analytics_endpoints(async_client: AsyncClient, admin_headers: dict):
    # Overview
    overview_resp = await async_client.get(
        "/api/v1/admin/analytics/overview?days=7", headers=admin_headers
    )
    assert overview_resp.status_code == 200
    data = overview_resp.json()
    assert "total_events" in data
    assert "successful_logins" in data

    # Event counts
    events_resp = await async_client.get(
        "/api/v1/admin/analytics/events?days=7", headers=admin_headers
    )
    assert events_resp.status_code == 200
    assert isinstance(events_resp.json(), list)

