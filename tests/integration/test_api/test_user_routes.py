"""API Integration Tests for User Profile Routes (Phase 8: Layer 5)."""

import pytest
from httpx import AsyncClient
from auth_service.models.user import User


@pytest.mark.asyncio
async def test_get_current_user_profile(
    async_client: AsyncClient, test_user: User, auth_headers: dict
):
    response = await async_client.get("/api/v1/users/me", headers=auth_headers)
    assert response.status_code == 200
    data = response.json()
    assert data["id"] == test_user.id
    assert data["email"] == test_user.email
    assert data["is_active"] is True


@pytest.mark.asyncio
async def test_update_current_user_profile(
    async_client: AsyncClient, test_user: User, auth_headers: dict
):
    update_payload = {
        "full_name": "Alexander The Great",
        "avatar_url": "https://example.com/avatar.png",
    }
    response = await async_client.put(
        "/api/v1/users/me", json=update_payload, headers=auth_headers
    )
    assert response.status_code == 200
    data = response.json()
    assert data["full_name"] == "Alexander The Great"
    assert data["avatar_url"] == "https://example.com/avatar.png"


@pytest.mark.asyncio
async def test_change_password_flow(
    async_client: AsyncClient, test_user: User, auth_headers: dict
):
    payload = {
        "current_password": "UserPassword123!@",
        "new_password": "BrandNewSecretPassword123!#",
    }
    response = await async_client.put(
        "/api/v1/users/me/password", json=payload, headers=auth_headers
    )
    assert response.status_code == 200

    # Verify can log in with new password
    login_resp = await async_client.post(
        "/api/v1/auth/login",
        json={"email": test_user.email, "password": "BrandNewSecretPassword123!#"},
    )
    assert login_resp.status_code == 200


@pytest.mark.asyncio
async def test_unauthenticated_request_rejected(async_client: AsyncClient):
    response = await async_client.get("/api/v1/users/me")
    assert response.status_code == 401
