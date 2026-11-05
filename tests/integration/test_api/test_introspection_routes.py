"""API Integration Tests for RFC 7662 Token Introspection & RFC 7009 Revocation (Phase 8)."""

import pytest
from httpx import AsyncClient
from auth_service.models.user import User


@pytest.mark.asyncio
async def test_token_introspection_active_token(
    async_client: AsyncClient, test_user: User
):
    # 1. Login to get access token
    login_resp = await async_client.post(
        "/api/v1/auth/login",
        json={"email": test_user.email, "password": "UserPassword123!@"},
    )
    tokens = login_resp.json()
    access_token = tokens["access_token"]

    # 2. Introspect token
    introspect_resp = await async_client.post(
        "/api/v1/oauth/introspect",
        json={"token": access_token},
    )
    assert introspect_resp.status_code == 200
    data = introspect_resp.json()
    assert data["active"] is True
    assert data["sub"] == test_user.id
    assert data["email"] == test_user.email

    # 3. Revoke token via RFC 7009
    revoke_resp = await async_client.post(
        "/api/v1/oauth/revoke",
        json={"token": access_token},
    )
    assert revoke_resp.status_code == 200

    # 4. Introspect again -> must report active: False
    introspect_again = await async_client.post(
        "/api/v1/oauth/introspect",
        json={"token": access_token},
    )
    assert introspect_again.status_code == 200
    assert introspect_again.json()["active"] is False

