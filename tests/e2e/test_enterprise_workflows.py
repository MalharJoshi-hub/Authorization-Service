"""End-to-End Enterprise Customer Journey and Lifecycle Workflows."""

import pytest
from httpx import AsyncClient


@pytest.mark.asyncio
async def test_complete_enterprise_lifecycle_workflow(async_client: AsyncClient):
    email = "lifecycle.user@enterprise.com"
    password = "EnterprisePassword2026!#"

    # Step 1: Self-service registration
    reg_resp = await async_client.post(
        "/api/v1/auth/register",
        json={
            "email": email,
            "password": password,
            "full_name": "Lifecycle User",
        },
    )
    assert reg_resp.status_code in (200, 201)
    user_info = reg_resp.json()
    assert user_info["email"] == email

    # Step 2: Primary Authentication (Login)
    login_resp = await async_client.post(
        "/api/v1/auth/login",
        json={"email": email, "password": password},
    )
    assert login_resp.status_code == 200
    token_bundle = login_resp.json()
    access_token = token_bundle["access_token"]
    refresh_token = token_bundle["refresh_token"]

    auth_headers = {"Authorization": f"Bearer {access_token}"}

    # Step 3: Self-Service Profile Retrieval
    me_resp = await async_client.get("/api/v1/users/me", headers=auth_headers)
    assert me_resp.status_code == 200
    me_data = me_resp.json()
    assert me_data["email"] == email

    # Step 4: Token Introspection (RFC 7662)
    introspect_resp = await async_client.post(
        "/api/v1/auth/introspect",
        json={"token": access_token},
    )
    assert introspect_resp.status_code == 200
    assert introspect_resp.json()["active"] is True

    # Step 5: Refresh Token Rotation
    refresh_resp = await async_client.post(
        "/api/v1/auth/refresh",
        json={"refresh_token": refresh_token},
    )
    assert refresh_resp.status_code == 200
    new_token_bundle = refresh_resp.json()
    new_access_token = new_token_bundle["access_token"]
    new_auth_headers = {"Authorization": f"Bearer {new_access_token}"}

    # Step 6: Authenticated Action with Rotated Token
    me_resp2 = await async_client.get("/api/v1/users/me", headers=new_auth_headers)
    assert me_resp2.status_code == 200

    # Step 7: Session Termination (Logout)
    logout_resp = await async_client.post("/api/v1/auth/logout", headers=new_auth_headers)
    assert logout_resp.status_code == 200

