"""API Integration Tests for Multi-Factor Authentication Router (Phase 8)."""

import pytest
from httpx import AsyncClient
from auth_service.models.user import User
from auth_service.services.mfa_service import mfa_service


@pytest.mark.asyncio
async def test_mfa_setup_and_verify_flow(
    async_client: AsyncClient, test_user: User, auth_headers: dict
):
    # 1. Check initial status
    status_resp = await async_client.get("/api/v1/mfa/status", headers=auth_headers)
    assert status_resp.status_code == 200
    assert status_resp.json()["is_enabled"] is False

    # 2. Initiate setup
    setup_resp = await async_client.post("/api/v1/mfa/setup", headers=auth_headers)
    assert setup_resp.status_code == 200
    setup_data = setup_resp.json()
    assert "secret" in setup_data
    secret = setup_data["secret"]

    # 3. Compute code and verify
    code = mfa_service.generate_totp_code(secret)
    verify_resp = await async_client.post(
        "/api/v1/mfa/verify", json={"code": code}, headers=auth_headers
    )
    assert verify_resp.status_code == 200
    verify_data = verify_resp.json()
    assert len(verify_data["backup_codes"]) == 10

    # 4. Status should now be enabled
    new_status = await async_client.get("/api/v1/mfa/status", headers=auth_headers)
    assert new_status.json()["is_enabled"] is True

    # 5. Disable MFA
    disable_code = mfa_service.generate_totp_code(secret)
    disable_resp = await async_client.post(
        "/api/v1/mfa/disable", json={"code": disable_code}, headers=auth_headers
    )
    assert disable_resp.status_code == 200

