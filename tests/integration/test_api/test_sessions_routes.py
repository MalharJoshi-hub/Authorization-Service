"""API Integration Tests for Device Session Routes (Phase 8)."""

import pytest
from httpx import AsyncClient
from auth_service.models.user import User


@pytest.mark.asyncio
async def test_session_management_flow(
    async_client: AsyncClient, test_user: User, auth_headers: dict
):
    # List active sessions
    response = await async_client.get("/api/v1/sessions", headers=auth_headers)
    assert response.status_code == 200
    assert isinstance(response.json(), list)

    # Revoke all
    revoke_resp = await async_client.delete("/api/v1/sessions", headers=auth_headers)
    assert revoke_resp.status_code == 200

