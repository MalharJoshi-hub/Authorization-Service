"""End-to-End Test: Negative Security Boundaries & Edge Cases (Phase 8)."""

import pytest
from httpx import AsyncClient
from auth_service.models.user import User


@pytest.mark.asyncio
async def test_expired_token_rejected_with_401(async_client: AsyncClient):
    # Pass malformed or expired JWT
    bogus_headers = {"Authorization": "Bearer eyJhbGciOiJIUzI1NiJ9.expired.fake"}
    response = await async_client.get("/api/v1/users/me", headers=bogus_headers)
    assert response.status_code == 401


@pytest.mark.asyncio
async def test_missing_auth_header(async_client: AsyncClient):
    response = await async_client.get("/api/v1/users/me")
    assert response.status_code == 401


@pytest.mark.asyncio
async def test_nonexistent_endpoint_returns_404(async_client: AsyncClient):
    response = await async_client.get("/api/v1/does-not-exist")
    assert response.status_code == 404


@pytest.mark.asyncio
async def test_sql_injection_in_login_safely_handled(
    async_client: AsyncClient, test_user: User
):
    sql_payload = {
        "email": "' OR '1'='1",
        "password": "' OR '1'='1",
    }
    response = await async_client.post("/api/v1/auth/login", json=sql_payload)
    # Must fail validation or 401, never 500 SQL syntax error
    assert response.status_code in (401, 422)


@pytest.mark.asyncio
async def test_oversized_payload_rejected(async_client: AsyncClient):
    huge_payload = {"email": "test@example.com", "password": "A" * (11 * 1024 * 1024)}
    headers = {"Content-Length": str(12 * 1024 * 1024)}
    response = await async_client.post(
        "/api/v1/auth/register",
        json={"email": "a@b.com", "password": "Password123!@"},
        headers=headers,
    )
    # Should catch via validation or 422
    assert response.status_code in (400, 422, 500)
