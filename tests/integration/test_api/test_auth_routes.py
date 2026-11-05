"""API Integration Tests for Authentication Router (Phase 8: Layer 5)."""

import pytest
from httpx import AsyncClient
from auth_service.models.tenant import Tenant
from auth_service.models.user import User


@pytest.mark.asyncio
async def test_register_new_user_success(async_client: AsyncClient, test_tenant: Tenant):
    payload = {
        "email": "fresh.user@example.com",
        "password": "StrongPassword123!#",
        "full_name": "Fresh User",
        "tenant_id": test_tenant.id,
    }
    response = await async_client.post("/api/v1/auth/register", json=payload)
    assert response.status_code == 201
    data = response.json()
    assert data["email"] == "fresh.user@example.com"
    assert data["is_verified"] is False
    assert "verification_token_preview" in data


@pytest.mark.asyncio
async def test_register_weak_password_rejected(async_client: AsyncClient, test_tenant: Tenant):
    payload = {
        "email": "weak@example.com",
        "password": "weak",
        "tenant_id": test_tenant.id,
    }
    response = await async_client.post("/api/v1/auth/register", json=payload)
    assert response.status_code == 422


@pytest.mark.asyncio
async def test_register_duplicate_email_rejected(
    async_client: AsyncClient, test_tenant: Tenant, test_user: User
):
    payload = {
        "email": test_user.email,
        "password": "StrongPassword123!#",
        "tenant_id": test_tenant.id,
    }
    response = await async_client.post("/api/v1/auth/register", json=payload)
    assert response.status_code == 409


@pytest.mark.asyncio
async def test_login_success_and_token_issuance(
    async_client: AsyncClient, test_tenant: Tenant, test_user: User
):
    payload = {
        "email": test_user.email,
        "password": "UserPassword123!@",
        "tenant_id": test_tenant.id,
    }
    response = await async_client.post("/api/v1/auth/login", json=payload)
    assert response.status_code == 200
    data = response.json()
    assert "access_token" in data
    assert "refresh_token" in data
    assert data["token_type"] == "bearer"
    assert data["user"]["email"] == test_user.email


@pytest.mark.asyncio
async def test_login_invalid_credentials_rejected(
    async_client: AsyncClient, test_tenant: Tenant, test_user: User
):
    payload = {
        "email": test_user.email,
        "password": "WrongPassword999!",
        "tenant_id": test_tenant.id,
    }
    response = await async_client.post("/api/v1/auth/login", json=payload)
    assert response.status_code == 401


@pytest.mark.asyncio
async def test_refresh_token_rotation_flow(
    async_client: AsyncClient, test_tenant: Tenant, test_user: User
):
    # 1. Login to get initial tokens
    login_resp = await async_client.post(
        "/api/v1/auth/login",
        json={"email": test_user.email, "password": "UserPassword123!@"},
    )
    refresh_token = login_resp.json()["refresh_token"]

    # 2. Exchange for new token pair
    rotate_resp = await async_client.post(
        "/api/v1/auth/refresh", json={"refresh_token": refresh_token}
    )
    assert rotate_resp.status_code == 200
    new_data = rotate_resp.json()
    assert "access_token" in new_data
    assert new_data["refresh_token"] != refresh_token


@pytest.mark.asyncio
async def test_logout_revokes_token(
    async_client: AsyncClient, test_tenant: Tenant, test_user: User
):
    login_resp = await async_client.post(
        "/api/v1/auth/login",
        json={"email": test_user.email, "password": "UserPassword123!@"},
    )
    tokens = login_resp.json()
    access_token = tokens["access_token"]
    refresh_token = tokens["refresh_token"]

    # Logout
    logout_resp = await async_client.post(
        "/api/v1/auth/logout",
        json={"refresh_token": refresh_token},
        headers={"Authorization": f"Bearer {access_token}"},
    )
    assert logout_resp.status_code == 200

    # Protected call with blacklisted access token should now fail
    protected_resp = await async_client.get(
        "/api/v1/users/me",
        headers={"Authorization": f"Bearer {access_token}"},
    )
    assert protected_resp.status_code == 401

