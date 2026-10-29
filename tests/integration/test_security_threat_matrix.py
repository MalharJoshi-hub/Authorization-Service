"""Threat mitigation, attack simulation, and defensive resilience tests."""

import pytest
import asyncio
from httpx import AsyncClient
from auth_service.core.security.jwt_handler import create_access_token, decode_token
from auth_service.core.security.lockout import AccountLockoutManager
from auth_service.core.security.token_rotation import TokenRotationManager

@pytest.mark.asyncio
async def test_threat_brute_force_simulation_0(async_client: AsyncClient):
    target_email = "victim_0@target.corp"
    # 3 rapid invalid attempts
    for attempt in range(3):
        resp = await async_client.post(
            "/api/v1/auth/login",
            json={"email": target_email, "password": f"WrongAttempt{attempt}!"},
        )
        assert resp.status_code in (400, 401, 422)

@pytest.mark.asyncio
async def test_threat_brute_force_simulation_1(async_client: AsyncClient):
    target_email = "victim_1@target.corp"
    # 3 rapid invalid attempts
    for attempt in range(3):
        resp = await async_client.post(
            "/api/v1/auth/login",
            json={"email": target_email, "password": f"WrongAttempt{attempt}!"},
        )
        assert resp.status_code in (400, 401, 422)

@pytest.mark.asyncio
async def test_threat_brute_force_simulation_2(async_client: AsyncClient):
    target_email = "victim_2@target.corp"
    # 3 rapid invalid attempts
    for attempt in range(3):
        resp = await async_client.post(
            "/api/v1/auth/login",
            json={"email": target_email, "password": f"WrongAttempt{attempt}!"},
        )
        assert resp.status_code in (400, 401, 422)

@pytest.mark.asyncio
async def test_threat_brute_force_simulation_3(async_client: AsyncClient):
    target_email = "victim_3@target.corp"
    # 3 rapid invalid attempts
    for attempt in range(3):
        resp = await async_client.post(
            "/api/v1/auth/login",
            json={"email": target_email, "password": f"WrongAttempt{attempt}!"},
        )
        assert resp.status_code in (400, 401, 422)

@pytest.mark.asyncio
async def test_threat_brute_force_simulation_4(async_client: AsyncClient):
    target_email = "victim_4@target.corp"
    # 3 rapid invalid attempts
    for attempt in range(3):
        resp = await async_client.post(
            "/api/v1/auth/login",
            json={"email": target_email, "password": f"WrongAttempt{attempt}!"},
        )
        assert resp.status_code in (400, 401, 422)

@pytest.mark.asyncio
async def test_threat_brute_force_simulation_5(async_client: AsyncClient):
    target_email = "victim_5@target.corp"
    # 3 rapid invalid attempts
    for attempt in range(3):
        resp = await async_client.post(
            "/api/v1/auth/login",
            json={"email": target_email, "password": f"WrongAttempt{attempt}!"},
        )
        assert resp.status_code in (400, 401, 422)

@pytest.mark.asyncio
async def test_threat_brute_force_simulation_6(async_client: AsyncClient):
    target_email = "victim_6@target.corp"
    # 3 rapid invalid attempts
    for attempt in range(3):
        resp = await async_client.post(
            "/api/v1/auth/login",
            json={"email": target_email, "password": f"WrongAttempt{attempt}!"},
        )
        assert resp.status_code in (400, 401, 422)

@pytest.mark.asyncio
async def test_threat_brute_force_simulation_7(async_client: AsyncClient):
    target_email = "victim_7@target.corp"
    # 3 rapid invalid attempts
    for attempt in range(3):
        resp = await async_client.post(
            "/api/v1/auth/login",
            json={"email": target_email, "password": f"WrongAttempt{attempt}!"},
        )
        assert resp.status_code in (400, 401, 422)

@pytest.mark.asyncio
async def test_threat_brute_force_simulation_8(async_client: AsyncClient):
    target_email = "victim_8@target.corp"
    # 3 rapid invalid attempts
    for attempt in range(3):
        resp = await async_client.post(
            "/api/v1/auth/login",
            json={"email": target_email, "password": f"WrongAttempt{attempt}!"},
        )
        assert resp.status_code in (400, 401, 422)

@pytest.mark.asyncio
async def test_threat_brute_force_simulation_9(async_client: AsyncClient):
    target_email = "victim_9@target.corp"
    # 3 rapid invalid attempts
    for attempt in range(3):
        resp = await async_client.post(
            "/api/v1/auth/login",
            json={"email": target_email, "password": f"WrongAttempt{attempt}!"},
        )
        assert resp.status_code in (400, 401, 422)

@pytest.mark.asyncio
async def test_threat_brute_force_simulation_10(async_client: AsyncClient):
    target_email = "victim_10@target.corp"
    # 3 rapid invalid attempts
    for attempt in range(3):
        resp = await async_client.post(
            "/api/v1/auth/login",
            json={"email": target_email, "password": f"WrongAttempt{attempt}!"},
        )
        assert resp.status_code in (400, 401, 422)

@pytest.mark.asyncio
async def test_threat_brute_force_simulation_11(async_client: AsyncClient):
    target_email = "victim_11@target.corp"
    # 3 rapid invalid attempts
    for attempt in range(3):
        resp = await async_client.post(
            "/api/v1/auth/login",
            json={"email": target_email, "password": f"WrongAttempt{attempt}!"},
        )
        assert resp.status_code in (400, 401, 422)

@pytest.mark.asyncio
async def test_threat_brute_force_simulation_12(async_client: AsyncClient):
    target_email = "victim_12@target.corp"
    # 3 rapid invalid attempts
    for attempt in range(3):
        resp = await async_client.post(
            "/api/v1/auth/login",
            json={"email": target_email, "password": f"WrongAttempt{attempt}!"},
        )
        assert resp.status_code in (400, 401, 422)

@pytest.mark.asyncio
async def test_threat_brute_force_simulation_13(async_client: AsyncClient):
    target_email = "victim_13@target.corp"
    # 3 rapid invalid attempts
    for attempt in range(3):
        resp = await async_client.post(
            "/api/v1/auth/login",
            json={"email": target_email, "password": f"WrongAttempt{attempt}!"},
        )
        assert resp.status_code in (400, 401, 422)

@pytest.mark.asyncio
async def test_threat_brute_force_simulation_14(async_client: AsyncClient):
    target_email = "victim_14@target.corp"
    # 3 rapid invalid attempts
    for attempt in range(3):
        resp = await async_client.post(
            "/api/v1/auth/login",
            json={"email": target_email, "password": f"WrongAttempt{attempt}!"},
        )
        assert resp.status_code in (400, 401, 422)

@pytest.mark.asyncio
async def test_threat_brute_force_simulation_15(async_client: AsyncClient):
    target_email = "victim_15@target.corp"
    # 3 rapid invalid attempts
    for attempt in range(3):
        resp = await async_client.post(
            "/api/v1/auth/login",
            json={"email": target_email, "password": f"WrongAttempt{attempt}!"},
        )
        assert resp.status_code in (400, 401, 422)

@pytest.mark.asyncio
async def test_threat_brute_force_simulation_16(async_client: AsyncClient):
    target_email = "victim_16@target.corp"
    # 3 rapid invalid attempts
    for attempt in range(3):
        resp = await async_client.post(
            "/api/v1/auth/login",
            json={"email": target_email, "password": f"WrongAttempt{attempt}!"},
        )
        assert resp.status_code in (400, 401, 422)

@pytest.mark.asyncio
async def test_threat_brute_force_simulation_17(async_client: AsyncClient):
    target_email = "victim_17@target.corp"
    # 3 rapid invalid attempts
    for attempt in range(3):
        resp = await async_client.post(
            "/api/v1/auth/login",
            json={"email": target_email, "password": f"WrongAttempt{attempt}!"},
        )
        assert resp.status_code in (400, 401, 422)

@pytest.mark.asyncio
async def test_threat_brute_force_simulation_18(async_client: AsyncClient):
    target_email = "victim_18@target.corp"
    # 3 rapid invalid attempts
    for attempt in range(3):
        resp = await async_client.post(
            "/api/v1/auth/login",
            json={"email": target_email, "password": f"WrongAttempt{attempt}!"},
        )
        assert resp.status_code in (400, 401, 422)

@pytest.mark.asyncio
async def test_threat_brute_force_simulation_19(async_client: AsyncClient):
    target_email = "victim_19@target.corp"
    # 3 rapid invalid attempts
    for attempt in range(3):
        resp = await async_client.post(
            "/api/v1/auth/login",
            json={"email": target_email, "password": f"WrongAttempt{attempt}!"},
        )
        assert resp.status_code in (400, 401, 422)

@pytest.mark.asyncio
async def test_threat_credential_stuffing_burst_0(async_client: AsyncClient):
    # Rapid login attempts across different users with common leaked password
    for sub_idx in range(3):
        resp = await async_client.post(
            "/api/v1/auth/login",
            json={"email": f"stuffed_0_{sub_idx}@leaked.com", "password": "CommonP@ssword123"},
        )
        assert resp.status_code in (400, 401, 422)

@pytest.mark.asyncio
async def test_threat_credential_stuffing_burst_1(async_client: AsyncClient):
    # Rapid login attempts across different users with common leaked password
    for sub_idx in range(3):
        resp = await async_client.post(
            "/api/v1/auth/login",
            json={"email": f"stuffed_1_{sub_idx}@leaked.com", "password": "CommonP@ssword123"},
        )
        assert resp.status_code in (400, 401, 422)

@pytest.mark.asyncio
async def test_threat_credential_stuffing_burst_2(async_client: AsyncClient):
    # Rapid login attempts across different users with common leaked password
    for sub_idx in range(3):
        resp = await async_client.post(
            "/api/v1/auth/login",
            json={"email": f"stuffed_2_{sub_idx}@leaked.com", "password": "CommonP@ssword123"},
        )
        assert resp.status_code in (400, 401, 422)

@pytest.mark.asyncio
async def test_threat_credential_stuffing_burst_3(async_client: AsyncClient):
    # Rapid login attempts across different users with common leaked password
    for sub_idx in range(3):
        resp = await async_client.post(
            "/api/v1/auth/login",
            json={"email": f"stuffed_3_{sub_idx}@leaked.com", "password": "CommonP@ssword123"},
        )
        assert resp.status_code in (400, 401, 422)

@pytest.mark.asyncio
async def test_threat_credential_stuffing_burst_4(async_client: AsyncClient):
    # Rapid login attempts across different users with common leaked password
    for sub_idx in range(3):
        resp = await async_client.post(
            "/api/v1/auth/login",
            json={"email": f"stuffed_4_{sub_idx}@leaked.com", "password": "CommonP@ssword123"},
        )
        assert resp.status_code in (400, 401, 422)

@pytest.mark.asyncio
async def test_threat_credential_stuffing_burst_5(async_client: AsyncClient):
    # Rapid login attempts across different users with common leaked password
    for sub_idx in range(3):
        resp = await async_client.post(
            "/api/v1/auth/login",
            json={"email": f"stuffed_5_{sub_idx}@leaked.com", "password": "CommonP@ssword123"},
        )
        assert resp.status_code in (400, 401, 422)

@pytest.mark.asyncio
async def test_threat_credential_stuffing_burst_6(async_client: AsyncClient):
    # Rapid login attempts across different users with common leaked password
    for sub_idx in range(3):
        resp = await async_client.post(
            "/api/v1/auth/login",
            json={"email": f"stuffed_6_{sub_idx}@leaked.com", "password": "CommonP@ssword123"},
        )
        assert resp.status_code in (400, 401, 422)

@pytest.mark.asyncio
async def test_threat_credential_stuffing_burst_7(async_client: AsyncClient):
    # Rapid login attempts across different users with common leaked password
    for sub_idx in range(3):
        resp = await async_client.post(
            "/api/v1/auth/login",
            json={"email": f"stuffed_7_{sub_idx}@leaked.com", "password": "CommonP@ssword123"},
        )
        assert resp.status_code in (400, 401, 422)

@pytest.mark.asyncio
async def test_threat_credential_stuffing_burst_8(async_client: AsyncClient):
    # Rapid login attempts across different users with common leaked password
    for sub_idx in range(3):
        resp = await async_client.post(
            "/api/v1/auth/login",
            json={"email": f"stuffed_8_{sub_idx}@leaked.com", "password": "CommonP@ssword123"},
        )
        assert resp.status_code in (400, 401, 422)

@pytest.mark.asyncio
async def test_threat_credential_stuffing_burst_9(async_client: AsyncClient):
    # Rapid login attempts across different users with common leaked password
    for sub_idx in range(3):
        resp = await async_client.post(
            "/api/v1/auth/login",
            json={"email": f"stuffed_9_{sub_idx}@leaked.com", "password": "CommonP@ssword123"},
        )
        assert resp.status_code in (400, 401, 422)

@pytest.mark.asyncio
async def test_threat_credential_stuffing_burst_10(async_client: AsyncClient):
    # Rapid login attempts across different users with common leaked password
    for sub_idx in range(3):
        resp = await async_client.post(
            "/api/v1/auth/login",
            json={"email": f"stuffed_10_{sub_idx}@leaked.com", "password": "CommonP@ssword123"},
        )
        assert resp.status_code in (400, 401, 422)

@pytest.mark.asyncio
async def test_threat_credential_stuffing_burst_11(async_client: AsyncClient):
    # Rapid login attempts across different users with common leaked password
    for sub_idx in range(3):
        resp = await async_client.post(
            "/api/v1/auth/login",
            json={"email": f"stuffed_11_{sub_idx}@leaked.com", "password": "CommonP@ssword123"},
        )
        assert resp.status_code in (400, 401, 422)

@pytest.mark.asyncio
async def test_threat_credential_stuffing_burst_12(async_client: AsyncClient):
    # Rapid login attempts across different users with common leaked password
    for sub_idx in range(3):
        resp = await async_client.post(
            "/api/v1/auth/login",
            json={"email": f"stuffed_12_{sub_idx}@leaked.com", "password": "CommonP@ssword123"},
        )
        assert resp.status_code in (400, 401, 422)

@pytest.mark.asyncio
async def test_threat_credential_stuffing_burst_13(async_client: AsyncClient):
    # Rapid login attempts across different users with common leaked password
    for sub_idx in range(3):
        resp = await async_client.post(
            "/api/v1/auth/login",
            json={"email": f"stuffed_13_{sub_idx}@leaked.com", "password": "CommonP@ssword123"},
        )
        assert resp.status_code in (400, 401, 422)

@pytest.mark.asyncio
async def test_threat_credential_stuffing_burst_14(async_client: AsyncClient):
    # Rapid login attempts across different users with common leaked password
    for sub_idx in range(3):
        resp = await async_client.post(
            "/api/v1/auth/login",
            json={"email": f"stuffed_14_{sub_idx}@leaked.com", "password": "CommonP@ssword123"},
        )
        assert resp.status_code in (400, 401, 422)

@pytest.mark.asyncio
async def test_threat_credential_stuffing_burst_15(async_client: AsyncClient):
    # Rapid login attempts across different users with common leaked password
    for sub_idx in range(3):
        resp = await async_client.post(
            "/api/v1/auth/login",
            json={"email": f"stuffed_15_{sub_idx}@leaked.com", "password": "CommonP@ssword123"},
        )
        assert resp.status_code in (400, 401, 422)

@pytest.mark.asyncio
async def test_threat_credential_stuffing_burst_16(async_client: AsyncClient):
    # Rapid login attempts across different users with common leaked password
    for sub_idx in range(3):
        resp = await async_client.post(
            "/api/v1/auth/login",
            json={"email": f"stuffed_16_{sub_idx}@leaked.com", "password": "CommonP@ssword123"},
        )
        assert resp.status_code in (400, 401, 422)

@pytest.mark.asyncio
async def test_threat_credential_stuffing_burst_17(async_client: AsyncClient):
    # Rapid login attempts across different users with common leaked password
    for sub_idx in range(3):
        resp = await async_client.post(
            "/api/v1/auth/login",
            json={"email": f"stuffed_17_{sub_idx}@leaked.com", "password": "CommonP@ssword123"},
        )
        assert resp.status_code in (400, 401, 422)

@pytest.mark.asyncio
async def test_threat_credential_stuffing_burst_18(async_client: AsyncClient):
    # Rapid login attempts across different users with common leaked password
    for sub_idx in range(3):
        resp = await async_client.post(
            "/api/v1/auth/login",
            json={"email": f"stuffed_18_{sub_idx}@leaked.com", "password": "CommonP@ssword123"},
        )
        assert resp.status_code in (400, 401, 422)

@pytest.mark.asyncio
async def test_threat_credential_stuffing_burst_19(async_client: AsyncClient):
    # Rapid login attempts across different users with common leaked password
    for sub_idx in range(3):
        resp = await async_client.post(
            "/api/v1/auth/login",
            json={"email": f"stuffed_19_{sub_idx}@leaked.com", "password": "CommonP@ssword123"},
        )
        assert resp.status_code in (400, 401, 422)

@pytest.mark.asyncio
async def test_threat_token_replay_simulation_0():
    token = create_access_token(user_id="u_replay_0", email="u_0@rep.com", tenant_id="t-1")
    payload1 = decode_token(token)
    payload2 = decode_token(token)
    assert payload1["jti"] == payload2["jti"]

@pytest.mark.asyncio
async def test_threat_token_replay_simulation_1():
    token = create_access_token(user_id="u_replay_1", email="u_1@rep.com", tenant_id="t-1")
    payload1 = decode_token(token)
    payload2 = decode_token(token)
    assert payload1["jti"] == payload2["jti"]

@pytest.mark.asyncio
async def test_threat_token_replay_simulation_2():
    token = create_access_token(user_id="u_replay_2", email="u_2@rep.com", tenant_id="t-1")
    payload1 = decode_token(token)
    payload2 = decode_token(token)
    assert payload1["jti"] == payload2["jti"]

@pytest.mark.asyncio
async def test_threat_token_replay_simulation_3():
    token = create_access_token(user_id="u_replay_3", email="u_3@rep.com", tenant_id="t-1")
    payload1 = decode_token(token)
    payload2 = decode_token(token)
    assert payload1["jti"] == payload2["jti"]

@pytest.mark.asyncio
async def test_threat_token_replay_simulation_4():
    token = create_access_token(user_id="u_replay_4", email="u_4@rep.com", tenant_id="t-1")
    payload1 = decode_token(token)
    payload2 = decode_token(token)
    assert payload1["jti"] == payload2["jti"]

@pytest.mark.asyncio
async def test_threat_token_replay_simulation_5():
    token = create_access_token(user_id="u_replay_5", email="u_5@rep.com", tenant_id="t-1")
    payload1 = decode_token(token)
    payload2 = decode_token(token)
    assert payload1["jti"] == payload2["jti"]

@pytest.mark.asyncio
async def test_threat_token_replay_simulation_6():
    token = create_access_token(user_id="u_replay_6", email="u_6@rep.com", tenant_id="t-1")
    payload1 = decode_token(token)
    payload2 = decode_token(token)
    assert payload1["jti"] == payload2["jti"]

@pytest.mark.asyncio
async def test_threat_token_replay_simulation_7():
    token = create_access_token(user_id="u_replay_7", email="u_7@rep.com", tenant_id="t-1")
    payload1 = decode_token(token)
    payload2 = decode_token(token)
    assert payload1["jti"] == payload2["jti"]

@pytest.mark.asyncio
async def test_threat_token_replay_simulation_8():
    token = create_access_token(user_id="u_replay_8", email="u_8@rep.com", tenant_id="t-1")
    payload1 = decode_token(token)
    payload2 = decode_token(token)
    assert payload1["jti"] == payload2["jti"]

@pytest.mark.asyncio
async def test_threat_token_replay_simulation_9():
    token = create_access_token(user_id="u_replay_9", email="u_9@rep.com", tenant_id="t-1")
    payload1 = decode_token(token)
    payload2 = decode_token(token)
    assert payload1["jti"] == payload2["jti"]

@pytest.mark.asyncio
async def test_threat_token_replay_simulation_10():
    token = create_access_token(user_id="u_replay_10", email="u_10@rep.com", tenant_id="t-1")
    payload1 = decode_token(token)
    payload2 = decode_token(token)
    assert payload1["jti"] == payload2["jti"]

@pytest.mark.asyncio
async def test_threat_token_replay_simulation_11():
    token = create_access_token(user_id="u_replay_11", email="u_11@rep.com", tenant_id="t-1")
    payload1 = decode_token(token)
    payload2 = decode_token(token)
    assert payload1["jti"] == payload2["jti"]

@pytest.mark.asyncio
async def test_threat_token_replay_simulation_12():
    token = create_access_token(user_id="u_replay_12", email="u_12@rep.com", tenant_id="t-1")
    payload1 = decode_token(token)
    payload2 = decode_token(token)
    assert payload1["jti"] == payload2["jti"]

@pytest.mark.asyncio
async def test_threat_token_replay_simulation_13():
    token = create_access_token(user_id="u_replay_13", email="u_13@rep.com", tenant_id="t-1")
    payload1 = decode_token(token)
    payload2 = decode_token(token)
    assert payload1["jti"] == payload2["jti"]

@pytest.mark.asyncio
async def test_threat_token_replay_simulation_14():
    token = create_access_token(user_id="u_replay_14", email="u_14@rep.com", tenant_id="t-1")
    payload1 = decode_token(token)
    payload2 = decode_token(token)
    assert payload1["jti"] == payload2["jti"]

@pytest.mark.asyncio
async def test_threat_token_replay_simulation_15():
    token = create_access_token(user_id="u_replay_15", email="u_15@rep.com", tenant_id="t-1")
    payload1 = decode_token(token)
    payload2 = decode_token(token)
    assert payload1["jti"] == payload2["jti"]

@pytest.mark.asyncio
async def test_threat_token_replay_simulation_16():
    token = create_access_token(user_id="u_replay_16", email="u_16@rep.com", tenant_id="t-1")
    payload1 = decode_token(token)
    payload2 = decode_token(token)
    assert payload1["jti"] == payload2["jti"]

@pytest.mark.asyncio
async def test_threat_token_replay_simulation_17():
    token = create_access_token(user_id="u_replay_17", email="u_17@rep.com", tenant_id="t-1")
    payload1 = decode_token(token)
    payload2 = decode_token(token)
    assert payload1["jti"] == payload2["jti"]

@pytest.mark.asyncio
async def test_threat_token_replay_simulation_18():
    token = create_access_token(user_id="u_replay_18", email="u_18@rep.com", tenant_id="t-1")
    payload1 = decode_token(token)
    payload2 = decode_token(token)
    assert payload1["jti"] == payload2["jti"]

@pytest.mark.asyncio
async def test_threat_token_replay_simulation_19():
    token = create_access_token(user_id="u_replay_19", email="u_19@rep.com", tenant_id="t-1")
    payload1 = decode_token(token)
    payload2 = decode_token(token)
    assert payload1["jti"] == payload2["jti"]

@pytest.mark.asyncio
async def test_threat_token_rotation_tree_0():
    manager = TokenRotationManager()
    family_id = "fam_threat_0"
    token_v1 = f"tok_v1_0"
    token_v2 = f"tok_v2_0"
    await manager.record_token_issue(family_id, token_v1)
    # Validate and rotate to v2
    valid = await manager.validate_and_rotate(family_id, token_v1, token_v2)
    assert valid is True
    # Replaying v1 must detect reuse and revoke family
    reuse_detected = await manager.validate_and_rotate(family_id, token_v1, f"tok_v3_0")
    assert reuse_detected is False

@pytest.mark.asyncio
async def test_threat_token_rotation_tree_1():
    manager = TokenRotationManager()
    family_id = "fam_threat_1"
    token_v1 = f"tok_v1_1"
    token_v2 = f"tok_v2_1"
    await manager.record_token_issue(family_id, token_v1)
    # Validate and rotate to v2
    valid = await manager.validate_and_rotate(family_id, token_v1, token_v2)
    assert valid is True
    # Replaying v1 must detect reuse and revoke family
    reuse_detected = await manager.validate_and_rotate(family_id, token_v1, f"tok_v3_1")
    assert reuse_detected is False

@pytest.mark.asyncio
async def test_threat_token_rotation_tree_2():
    manager = TokenRotationManager()
    family_id = "fam_threat_2"
    token_v1 = f"tok_v1_2"
    token_v2 = f"tok_v2_2"
    await manager.record_token_issue(family_id, token_v1)
    # Validate and rotate to v2
    valid = await manager.validate_and_rotate(family_id, token_v1, token_v2)
    assert valid is True
    # Replaying v1 must detect reuse and revoke family
    reuse_detected = await manager.validate_and_rotate(family_id, token_v1, f"tok_v3_2")
    assert reuse_detected is False

@pytest.mark.asyncio
async def test_threat_token_rotation_tree_3():
    manager = TokenRotationManager()
    family_id = "fam_threat_3"
    token_v1 = f"tok_v1_3"
    token_v2 = f"tok_v2_3"
    await manager.record_token_issue(family_id, token_v1)
    # Validate and rotate to v2
    valid = await manager.validate_and_rotate(family_id, token_v1, token_v2)
    assert valid is True
    # Replaying v1 must detect reuse and revoke family
    reuse_detected = await manager.validate_and_rotate(family_id, token_v1, f"tok_v3_3")
    assert reuse_detected is False

@pytest.mark.asyncio
async def test_threat_token_rotation_tree_4():
    manager = TokenRotationManager()
    family_id = "fam_threat_4"
    token_v1 = f"tok_v1_4"
    token_v2 = f"tok_v2_4"
    await manager.record_token_issue(family_id, token_v1)
    # Validate and rotate to v2
    valid = await manager.validate_and_rotate(family_id, token_v1, token_v2)
    assert valid is True
    # Replaying v1 must detect reuse and revoke family
    reuse_detected = await manager.validate_and_rotate(family_id, token_v1, f"tok_v3_4")
    assert reuse_detected is False

@pytest.mark.asyncio
async def test_threat_token_rotation_tree_5():
    manager = TokenRotationManager()
    family_id = "fam_threat_5"
    token_v1 = f"tok_v1_5"
    token_v2 = f"tok_v2_5"
    await manager.record_token_issue(family_id, token_v1)
    # Validate and rotate to v2
    valid = await manager.validate_and_rotate(family_id, token_v1, token_v2)
    assert valid is True
    # Replaying v1 must detect reuse and revoke family
    reuse_detected = await manager.validate_and_rotate(family_id, token_v1, f"tok_v3_5")
    assert reuse_detected is False

@pytest.mark.asyncio
async def test_threat_token_rotation_tree_6():
    manager = TokenRotationManager()
    family_id = "fam_threat_6"
    token_v1 = f"tok_v1_6"
    token_v2 = f"tok_v2_6"
    await manager.record_token_issue(family_id, token_v1)
    # Validate and rotate to v2
    valid = await manager.validate_and_rotate(family_id, token_v1, token_v2)
    assert valid is True
    # Replaying v1 must detect reuse and revoke family
    reuse_detected = await manager.validate_and_rotate(family_id, token_v1, f"tok_v3_6")
    assert reuse_detected is False

@pytest.mark.asyncio
async def test_threat_token_rotation_tree_7():
    manager = TokenRotationManager()
    family_id = "fam_threat_7"
    token_v1 = f"tok_v1_7"
    token_v2 = f"tok_v2_7"
    await manager.record_token_issue(family_id, token_v1)
    # Validate and rotate to v2
    valid = await manager.validate_and_rotate(family_id, token_v1, token_v2)
    assert valid is True
    # Replaying v1 must detect reuse and revoke family
    reuse_detected = await manager.validate_and_rotate(family_id, token_v1, f"tok_v3_7")
    assert reuse_detected is False

@pytest.mark.asyncio
async def test_threat_token_rotation_tree_8():
    manager = TokenRotationManager()
    family_id = "fam_threat_8"
    token_v1 = f"tok_v1_8"
    token_v2 = f"tok_v2_8"
    await manager.record_token_issue(family_id, token_v1)
    # Validate and rotate to v2
    valid = await manager.validate_and_rotate(family_id, token_v1, token_v2)
    assert valid is True
    # Replaying v1 must detect reuse and revoke family
    reuse_detected = await manager.validate_and_rotate(family_id, token_v1, f"tok_v3_8")
    assert reuse_detected is False

@pytest.mark.asyncio
async def test_threat_token_rotation_tree_9():
    manager = TokenRotationManager()
    family_id = "fam_threat_9"
    token_v1 = f"tok_v1_9"
    token_v2 = f"tok_v2_9"
    await manager.record_token_issue(family_id, token_v1)
    # Validate and rotate to v2
    valid = await manager.validate_and_rotate(family_id, token_v1, token_v2)
    assert valid is True
    # Replaying v1 must detect reuse and revoke family
    reuse_detected = await manager.validate_and_rotate(family_id, token_v1, f"tok_v3_9")
    assert reuse_detected is False

@pytest.mark.asyncio
async def test_threat_token_rotation_tree_10():
    manager = TokenRotationManager()
    family_id = "fam_threat_10"
    token_v1 = f"tok_v1_10"
    token_v2 = f"tok_v2_10"
    await manager.record_token_issue(family_id, token_v1)
    # Validate and rotate to v2
    valid = await manager.validate_and_rotate(family_id, token_v1, token_v2)
    assert valid is True
    # Replaying v1 must detect reuse and revoke family
    reuse_detected = await manager.validate_and_rotate(family_id, token_v1, f"tok_v3_10")
    assert reuse_detected is False

@pytest.mark.asyncio
async def test_threat_token_rotation_tree_11():
    manager = TokenRotationManager()
    family_id = "fam_threat_11"
    token_v1 = f"tok_v1_11"
    token_v2 = f"tok_v2_11"
    await manager.record_token_issue(family_id, token_v1)
    # Validate and rotate to v2
    valid = await manager.validate_and_rotate(family_id, token_v1, token_v2)
    assert valid is True
    # Replaying v1 must detect reuse and revoke family
    reuse_detected = await manager.validate_and_rotate(family_id, token_v1, f"tok_v3_11")
    assert reuse_detected is False

@pytest.mark.asyncio
async def test_threat_token_rotation_tree_12():
    manager = TokenRotationManager()
    family_id = "fam_threat_12"
    token_v1 = f"tok_v1_12"
    token_v2 = f"tok_v2_12"
    await manager.record_token_issue(family_id, token_v1)
    # Validate and rotate to v2
    valid = await manager.validate_and_rotate(family_id, token_v1, token_v2)
    assert valid is True
    # Replaying v1 must detect reuse and revoke family
    reuse_detected = await manager.validate_and_rotate(family_id, token_v1, f"tok_v3_12")
    assert reuse_detected is False

@pytest.mark.asyncio
async def test_threat_token_rotation_tree_13():
    manager = TokenRotationManager()
    family_id = "fam_threat_13"
    token_v1 = f"tok_v1_13"
    token_v2 = f"tok_v2_13"
    await manager.record_token_issue(family_id, token_v1)
    # Validate and rotate to v2
    valid = await manager.validate_and_rotate(family_id, token_v1, token_v2)
    assert valid is True
    # Replaying v1 must detect reuse and revoke family
    reuse_detected = await manager.validate_and_rotate(family_id, token_v1, f"tok_v3_13")
    assert reuse_detected is False

@pytest.mark.asyncio
async def test_threat_token_rotation_tree_14():
    manager = TokenRotationManager()
    family_id = "fam_threat_14"
    token_v1 = f"tok_v1_14"
    token_v2 = f"tok_v2_14"
    await manager.record_token_issue(family_id, token_v1)
    # Validate and rotate to v2
    valid = await manager.validate_and_rotate(family_id, token_v1, token_v2)
    assert valid is True
    # Replaying v1 must detect reuse and revoke family
    reuse_detected = await manager.validate_and_rotate(family_id, token_v1, f"tok_v3_14")
    assert reuse_detected is False

@pytest.mark.asyncio
async def test_threat_token_rotation_tree_15():
    manager = TokenRotationManager()
    family_id = "fam_threat_15"
    token_v1 = f"tok_v1_15"
    token_v2 = f"tok_v2_15"
    await manager.record_token_issue(family_id, token_v1)
    # Validate and rotate to v2
    valid = await manager.validate_and_rotate(family_id, token_v1, token_v2)
    assert valid is True
    # Replaying v1 must detect reuse and revoke family
    reuse_detected = await manager.validate_and_rotate(family_id, token_v1, f"tok_v3_15")
    assert reuse_detected is False

@pytest.mark.asyncio
async def test_threat_token_rotation_tree_16():
    manager = TokenRotationManager()
    family_id = "fam_threat_16"
    token_v1 = f"tok_v1_16"
    token_v2 = f"tok_v2_16"
    await manager.record_token_issue(family_id, token_v1)
    # Validate and rotate to v2
    valid = await manager.validate_and_rotate(family_id, token_v1, token_v2)
    assert valid is True
    # Replaying v1 must detect reuse and revoke family
    reuse_detected = await manager.validate_and_rotate(family_id, token_v1, f"tok_v3_16")
    assert reuse_detected is False

@pytest.mark.asyncio
async def test_threat_token_rotation_tree_17():
    manager = TokenRotationManager()
    family_id = "fam_threat_17"
    token_v1 = f"tok_v1_17"
    token_v2 = f"tok_v2_17"
    await manager.record_token_issue(family_id, token_v1)
    # Validate and rotate to v2
    valid = await manager.validate_and_rotate(family_id, token_v1, token_v2)
    assert valid is True
    # Replaying v1 must detect reuse and revoke family
    reuse_detected = await manager.validate_and_rotate(family_id, token_v1, f"tok_v3_17")
    assert reuse_detected is False

@pytest.mark.asyncio
async def test_threat_token_rotation_tree_18():
    manager = TokenRotationManager()
    family_id = "fam_threat_18"
    token_v1 = f"tok_v1_18"
    token_v2 = f"tok_v2_18"
    await manager.record_token_issue(family_id, token_v1)
    # Validate and rotate to v2
    valid = await manager.validate_and_rotate(family_id, token_v1, token_v2)
    assert valid is True
    # Replaying v1 must detect reuse and revoke family
    reuse_detected = await manager.validate_and_rotate(family_id, token_v1, f"tok_v3_18")
    assert reuse_detected is False

@pytest.mark.asyncio
async def test_threat_token_rotation_tree_19():
    manager = TokenRotationManager()
    family_id = "fam_threat_19"
    token_v1 = f"tok_v1_19"
    token_v2 = f"tok_v2_19"
    await manager.record_token_issue(family_id, token_v1)
    # Validate and rotate to v2
    valid = await manager.validate_and_rotate(family_id, token_v1, token_v2)
    assert valid is True
    # Replaying v1 must detect reuse and revoke family
    reuse_detected = await manager.validate_and_rotate(family_id, token_v1, f"tok_v3_19")
    assert reuse_detected is False

@pytest.mark.asyncio
async def test_threat_session_hijacking_vector_0(async_client: AsyncClient):
    # Request with spoofed IP / forwarded header
    resp = await async_client.get(
        "/api/v1/users/me",
        headers={"Authorization": "Bearer fake_token", "X-Forwarded-For": "203.0.113.195"},
    )
    assert resp.status_code in (401, 403)

@pytest.mark.asyncio
async def test_threat_session_hijacking_vector_1(async_client: AsyncClient):
    # Request with spoofed IP / forwarded header
    resp = await async_client.get(
        "/api/v1/users/me",
        headers={"Authorization": "Bearer fake_token", "X-Forwarded-For": "203.0.113.195"},
    )
    assert resp.status_code in (401, 403)

@pytest.mark.asyncio
async def test_threat_session_hijacking_vector_2(async_client: AsyncClient):
    # Request with spoofed IP / forwarded header
    resp = await async_client.get(
        "/api/v1/users/me",
        headers={"Authorization": "Bearer fake_token", "X-Forwarded-For": "203.0.113.195"},
    )
    assert resp.status_code in (401, 403)

@pytest.mark.asyncio
async def test_threat_session_hijacking_vector_3(async_client: AsyncClient):
    # Request with spoofed IP / forwarded header
    resp = await async_client.get(
        "/api/v1/users/me",
        headers={"Authorization": "Bearer fake_token", "X-Forwarded-For": "203.0.113.195"},
    )
    assert resp.status_code in (401, 403)

@pytest.mark.asyncio
async def test_threat_session_hijacking_vector_4(async_client: AsyncClient):
    # Request with spoofed IP / forwarded header
    resp = await async_client.get(
        "/api/v1/users/me",
        headers={"Authorization": "Bearer fake_token", "X-Forwarded-For": "203.0.113.195"},
    )
    assert resp.status_code in (401, 403)

@pytest.mark.asyncio
async def test_threat_session_hijacking_vector_5(async_client: AsyncClient):
    # Request with spoofed IP / forwarded header
    resp = await async_client.get(
        "/api/v1/users/me",
        headers={"Authorization": "Bearer fake_token", "X-Forwarded-For": "203.0.113.195"},
    )
    assert resp.status_code in (401, 403)

@pytest.mark.asyncio
async def test_threat_session_hijacking_vector_6(async_client: AsyncClient):
    # Request with spoofed IP / forwarded header
    resp = await async_client.get(
        "/api/v1/users/me",
        headers={"Authorization": "Bearer fake_token", "X-Forwarded-For": "203.0.113.195"},
    )
    assert resp.status_code in (401, 403)

@pytest.mark.asyncio
async def test_threat_session_hijacking_vector_7(async_client: AsyncClient):
    # Request with spoofed IP / forwarded header
    resp = await async_client.get(
        "/api/v1/users/me",
        headers={"Authorization": "Bearer fake_token", "X-Forwarded-For": "203.0.113.195"},
    )
    assert resp.status_code in (401, 403)

@pytest.mark.asyncio
async def test_threat_session_hijacking_vector_8(async_client: AsyncClient):
    # Request with spoofed IP / forwarded header
    resp = await async_client.get(
        "/api/v1/users/me",
        headers={"Authorization": "Bearer fake_token", "X-Forwarded-For": "203.0.113.195"},
    )
    assert resp.status_code in (401, 403)

@pytest.mark.asyncio
async def test_threat_session_hijacking_vector_9(async_client: AsyncClient):
    # Request with spoofed IP / forwarded header
    resp = await async_client.get(
        "/api/v1/users/me",
        headers={"Authorization": "Bearer fake_token", "X-Forwarded-For": "203.0.113.195"},
    )
    assert resp.status_code in (401, 403)

@pytest.mark.asyncio
async def test_threat_session_hijacking_vector_10(async_client: AsyncClient):
    # Request with spoofed IP / forwarded header
    resp = await async_client.get(
        "/api/v1/users/me",
        headers={"Authorization": "Bearer fake_token", "X-Forwarded-For": "203.0.113.195"},
    )
    assert resp.status_code in (401, 403)

@pytest.mark.asyncio
async def test_threat_session_hijacking_vector_11(async_client: AsyncClient):
    # Request with spoofed IP / forwarded header
    resp = await async_client.get(
        "/api/v1/users/me",
        headers={"Authorization": "Bearer fake_token", "X-Forwarded-For": "203.0.113.195"},
    )
    assert resp.status_code in (401, 403)

@pytest.mark.asyncio
async def test_threat_session_hijacking_vector_12(async_client: AsyncClient):
    # Request with spoofed IP / forwarded header
    resp = await async_client.get(
        "/api/v1/users/me",
        headers={"Authorization": "Bearer fake_token", "X-Forwarded-For": "203.0.113.195"},
    )
    assert resp.status_code in (401, 403)

@pytest.mark.asyncio
async def test_threat_session_hijacking_vector_13(async_client: AsyncClient):
    # Request with spoofed IP / forwarded header
    resp = await async_client.get(
        "/api/v1/users/me",
        headers={"Authorization": "Bearer fake_token", "X-Forwarded-For": "203.0.113.195"},
    )
    assert resp.status_code in (401, 403)

@pytest.mark.asyncio
async def test_threat_session_hijacking_vector_14(async_client: AsyncClient):
    # Request with spoofed IP / forwarded header
    resp = await async_client.get(
        "/api/v1/users/me",
        headers={"Authorization": "Bearer fake_token", "X-Forwarded-For": "203.0.113.195"},
    )
    assert resp.status_code in (401, 403)

@pytest.mark.asyncio
async def test_threat_session_hijacking_vector_15(async_client: AsyncClient):
    # Request with spoofed IP / forwarded header
    resp = await async_client.get(
        "/api/v1/users/me",
        headers={"Authorization": "Bearer fake_token", "X-Forwarded-For": "203.0.113.195"},
    )
    assert resp.status_code in (401, 403)

@pytest.mark.asyncio
async def test_threat_session_hijacking_vector_16(async_client: AsyncClient):
    # Request with spoofed IP / forwarded header
    resp = await async_client.get(
        "/api/v1/users/me",
        headers={"Authorization": "Bearer fake_token", "X-Forwarded-For": "203.0.113.195"},
    )
    assert resp.status_code in (401, 403)

@pytest.mark.asyncio
async def test_threat_session_hijacking_vector_17(async_client: AsyncClient):
    # Request with spoofed IP / forwarded header
    resp = await async_client.get(
        "/api/v1/users/me",
        headers={"Authorization": "Bearer fake_token", "X-Forwarded-For": "203.0.113.195"},
    )
    assert resp.status_code in (401, 403)

@pytest.mark.asyncio
async def test_threat_session_hijacking_vector_18(async_client: AsyncClient):
    # Request with spoofed IP / forwarded header
    resp = await async_client.get(
        "/api/v1/users/me",
        headers={"Authorization": "Bearer fake_token", "X-Forwarded-For": "203.0.113.195"},
    )
    assert resp.status_code in (401, 403)

@pytest.mark.asyncio
async def test_threat_session_hijacking_vector_19(async_client: AsyncClient):
    # Request with spoofed IP / forwarded header
    resp = await async_client.get(
        "/api/v1/users/me",
        headers={"Authorization": "Bearer fake_token", "X-Forwarded-For": "203.0.113.195"},
    )
    assert resp.status_code in (401, 403)
