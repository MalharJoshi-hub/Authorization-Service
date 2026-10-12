"""End-to-End Test: Refresh Token Theft & Reuse Attack Detection (Phase 8)."""

import pytest
from httpx import AsyncClient
from auth_service.models.tenant import Tenant
from auth_service.models.user import User


@pytest.mark.asyncio
async def test_detect_refresh_token_reuse_and_terminate_family(
    async_client: AsyncClient, test_tenant: Tenant, test_user: User
):
    # 1. Legit user logs in -> receives Token Pair 1
    login_resp = await async_client.post(
        "/api/v1/auth/login",
        json={"email": test_user.email, "password": "UserPassword123!@"},
    )
    tokens_1 = login_resp.json()
    refresh_token_1 = tokens_1["refresh_token"]

    # 2. Legit user rotates token -> receives Token Pair 2
    rotate_resp = await async_client.post(
        "/api/v1/auth/refresh",
        json={"refresh_token": refresh_token_1},
    )
    assert rotate_resp.status_code == 200
    tokens_2 = rotate_resp.json()
    refresh_token_2 = tokens_2["refresh_token"]

    # 3. Attacker intercepted Token 1 and replays it!
    # Expected: System flags REUSE ATTACK, blocks request with 401,
    # and immediately invalidates the entire token family!
    reuse_resp = await async_client.post(
        "/api/v1/auth/refresh",
        json={"refresh_token": refresh_token_1},
    )
    assert reuse_resp.status_code == 401
    assert "reuse" in reuse_resp.text.lower() or "revoked" in reuse_resp.text.lower()

    # 4. Legit user tries to use Token 2 (which belongs to the same compromised family)
    # Expected: Token 2 is NOW ALSO REVOKED because the whole family was terminated
    legit_attempt_resp = await async_client.post(
        "/api/v1/auth/refresh",
        json={"refresh_token": refresh_token_2},
    )
    assert legit_attempt_resp.status_code == 401
