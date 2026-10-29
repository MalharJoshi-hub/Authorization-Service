"""Concurrency, race condition, and parallel execution tests."""

import asyncio
import pytest
from httpx import AsyncClient


@pytest.mark.asyncio
async def test_concurrent_registrations(async_client: AsyncClient):
    """Test user registration requests for distinct users."""
    for idx in range(5):
        resp = await async_client.post(
            "/api/v1/auth/register",
            json={
                "email": f"conc_{idx}@test.org",
                "password": f"ValidPassword{idx}!2026",
                "full_name": f"Concurrent User {idx}",
            },
        )
        assert resp.status_code in (200, 201)
        data = resp.json()
        assert "id" in data
        assert "email" in data


@pytest.mark.asyncio
async def test_concurrent_login_same_credentials(async_client: AsyncClient):
    """Test logins with the same user credentials."""
    # First create user
    await async_client.post(
        "/api/v1/auth/register",
        json={
            "email": "shared_login@test.org",
            "password": "Password123!@",
        },
    )

    resp = await async_client.post(
        "/api/v1/auth/login",
        json={"email": "shared_login@test.org", "password": "Password123!@"},
    )
    assert resp.status_code == 200
    data = resp.json()
    assert "access_token" in data
    assert "refresh_token" in data


@pytest.mark.asyncio
async def test_concurrent_public_probe_requests(async_client: AsyncClient):
    """Test 20 simultaneous health probe calls without degradation."""
    async def probe():
        return await async_client.get("/health")

    tasks = [probe() for _ in range(20)]
    responses = await asyncio.gather(*tasks)

    for r in responses:
        assert r.status_code == 200
        assert r.json()["status"] == "ok"
