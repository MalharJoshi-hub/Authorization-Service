"""API Integration Tests for Webhook Routes (Phase 8)."""

import pytest
from httpx import AsyncClient


@pytest.mark.asyncio
async def test_webhook_crud_and_ping(async_client: AsyncClient, admin_headers: dict):
    # 1. Register webhook
    payload = {
        "url": "https://example.com/api/webhook-receiver",
        "events": ["user.created", "login.failed"],
        "description": "Integration Test Webhook",
    }
    response = await async_client.post("/api/v1/webhooks", json=payload, headers=admin_headers)
    assert response.status_code == 201
    data = response.json()
    assert data["url"] == payload["url"]
    webhook_id = data["id"]

    # 2. List webhooks
    list_resp = await async_client.get("/api/v1/webhooks", headers=admin_headers)
    assert list_resp.status_code == 200
    assert any(w["id"] == webhook_id for w in list_resp.json())

    # 3. Test ping
    ping_resp = await async_client.post(
        f"/api/v1/webhooks/{webhook_id}/ping", headers=admin_headers
    )
    assert ping_resp.status_code == 200

    # 4. Delete webhook
    del_resp = await async_client.delete(f"/api/v1/webhooks/{webhook_id}", headers=admin_headers)
    assert del_resp.status_code == 200
