"""API Integration Tests for Multi-Tenant Management (Phase 8: Layer 5)."""

import pytest
from httpx import AsyncClient


@pytest.mark.asyncio
async def test_tenant_crud_flow(async_client: AsyncClient, admin_headers: dict):
    # 1. Create tenant
    payload = {
        "name": "Stark Industries",
        "slug": "stark-industries",
        "plan": "enterprise",
    }
    response = await async_client.post("/api/v1/tenants", json=payload, headers=admin_headers)
    assert response.status_code == 201
    data = response.json()
    assert data["name"] == "Stark Industries"
    assert data["slug"] == "stark-industries"
    tenant_id = data["id"]

    # 2. Inspect tenant
    get_resp = await async_client.get(f"/api/v1/tenants/{tenant_id}", headers=admin_headers)
    assert get_resp.status_code == 200

    # 3. Get current tenant
    me_resp = await async_client.get("/api/v1/tenants/me", headers=admin_headers)
    assert me_resp.status_code == 200

    # 4. Invite member
    invite_resp = await async_client.post(
        "/api/v1/tenants/me/invites",
        json={"email": "pepper@stark.com", "role_name": "admin"},
        headers=admin_headers,
    )
    assert invite_resp.status_code == 200

