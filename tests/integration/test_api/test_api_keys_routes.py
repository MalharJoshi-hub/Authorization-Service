"""API Integration Tests for API Keys Lifecycle (Phase 8: Layer 5)."""

import pytest
from httpx import AsyncClient


@pytest.mark.asyncio
async def test_api_key_lifecycle(async_client: AsyncClient, admin_headers: dict):
    # 1. Create API key
    payload = {
        "name": "Integration Test Key",
        "scopes": ["read:users", "manage:api_keys"],
        "expires_in_days": 30,
    }
    response = await async_client.post("/api/v1/api-keys", json=payload, headers=admin_headers)
    assert response.status_code == 201
    data = response.json()
    assert "raw_key" in data
    assert data["raw_key"].startswith("aas_live_")
    key_id = data["id"]
    raw_key = data["raw_key"]

    # 2. List keys (raw secret masked)
    list_resp = await async_client.get("/api/v1/api-keys", headers=admin_headers)
    assert list_resp.status_code == 200
    keys = list_resp.json()
    assert any(k["id"] == key_id for k in keys)

    # 3. Inspect single key
    get_resp = await async_client.get(f"/api/v1/api-keys/{key_id}", headers=admin_headers)
    assert get_resp.status_code == 200
    assert get_resp.json()["is_active"] is True

    # 4. Revoke key
    del_resp = await async_client.delete(f"/api/v1/api-keys/{key_id}", headers=admin_headers)
    assert del_resp.status_code == 200

