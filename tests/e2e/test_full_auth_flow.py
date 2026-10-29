"""End-to-End Test: Complete User Authentication & Lifecycle Flow (Phase 8)."""

import pytest
from httpx import AsyncClient
from auth_service.models.tenant import Tenant


@pytest.mark.asyncio
async def test_complete_end_to_end_lifecycle(
    async_client: AsyncClient, test_tenant: Tenant
):
    email = "lifecycle.e2e@example.com"
    password = "E2EPassword2026!#"

    # 1. Registration
    reg_resp = await async_client.post(
        "/api/v1/auth/register",
        json={
            "email": email,
            "password": password,
            "full_name": "E2E Lifecycle User",
            "tenant_id": test_tenant.id,
        },
    )
    assert reg_resp.status_code == 201
    reg_data = reg_resp.json()
    verification_token = reg_data["verification_token_preview"]
    assert verification_token is not None

    # 2. Email Verification
    verify_resp = await async_client.post(
        "/api/v1/auth/verify-email",
        json={"token": verification_token},
    )
    assert verify_resp.status_code == 200

    # 3. Authenticate with credentials
    login_resp = await async_client.post(
        "/api/v1/auth/login",
        json={"email": email, "password": password, "tenant_id": test_tenant.id},
    )
    assert login_resp.status_code == 200
    tokens = login_resp.json()
    access_token = tokens["access_token"]
    refresh_token = tokens["refresh_token"]

    # 4. Access protected profile endpoint
    headers = {"Authorization": f"Bearer {access_token}", "X-Tenant-ID": test_tenant.id}
    me_resp = await async_client.get("/api/v1/users/me", headers=headers)
    assert me_resp.status_code == 200
    assert me_resp.json()["email"] == email

    # 5. Rotate refresh token
    refresh_resp = await async_client.post(
        "/api/v1/auth/refresh",
        json={"refresh_token": refresh_token},
    )
    assert refresh_resp.status_code == 200
    rotated_tokens = refresh_resp.json()
    new_access_token = rotated_tokens["access_token"]
    new_refresh_token = rotated_tokens["refresh_token"]
    assert new_refresh_token != refresh_token

    # 6. Access protected endpoint with new access token
    new_headers = {"Authorization": f"Bearer {new_access_token}", "X-Tenant-ID": test_tenant.id}
    me_after_refresh = await async_client.get("/api/v1/users/me", headers=new_headers)
    assert me_after_refresh.status_code == 200

    # 7. Logout and revoke session
    logout_resp = await async_client.post(
        "/api/v1/auth/logout",
        json={"refresh_token": new_refresh_token},
        headers=new_headers,
    )
    assert logout_resp.status_code == 200

    # 8. Verify access token is blacklisted
    denied_resp = await async_client.get("/api/v1/users/me", headers=new_headers)
    assert denied_resp.status_code == 401

    # 9. Verify refresh token is revoked
    revoked_refresh_resp = await async_client.post(
        "/api/v1/auth/refresh",
        json={"refresh_token": new_refresh_token},
    )
    assert revoked_refresh_resp.status_code == 401
