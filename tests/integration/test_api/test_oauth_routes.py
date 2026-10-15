"""API Integration Tests for OAuth2 Social Authentication (Phase 8: Layer 5)."""

import pytest
from httpx import AsyncClient


@pytest.mark.asyncio
async def test_list_oauth_providers(async_client: AsyncClient):
    response = await async_client.get("/api/v1/oauth/providers")
    assert response.status_code == 200
    providers = response.json()
    assert len(providers) >= 2
    names = [p["provider"] for p in providers]
    assert "google" in names
    assert "github" in names


@pytest.mark.asyncio
async def test_google_login_redirect(async_client: AsyncClient):
    response = await async_client.get("/api/v1/oauth/google", follow_redirects=False)
    assert response.status_code in (302, 307)
    assert "accounts.google.com" in response.headers["location"]


@pytest.mark.asyncio
async def test_github_login_redirect(async_client: AsyncClient):
    response = await async_client.get("/api/v1/oauth/github", follow_redirects=False)
    assert response.status_code in (302, 307)
    assert "github.com/login/oauth" in response.headers["location"]


@pytest.mark.asyncio
async def test_google_callback_mock_flow(async_client: AsyncClient):
    response = await async_client.get(
        "/api/v1/oauth/google/callback?code=mock_code_123456"
    )
    assert response.status_code == 200
    data = response.json()
    assert "access_token" in data
    assert "refresh_token" in data


@pytest.mark.asyncio
async def test_github_callback_mock_flow(async_client: AsyncClient):
    response = await async_client.get(
        "/api/v1/oauth/github/callback?code=mock_github_code_123"
    )
    assert response.status_code == 200
    data = response.json()
    assert "access_token" in data
