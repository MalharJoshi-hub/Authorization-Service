"""Unit Tests for Brute Force Account Lockout (Phase 8: Layer 1)."""

import pytest
from auth_service.core.security.lockout import lockout_manager


@pytest.mark.asyncio
async def test_lockout_records_and_triggers_lock():
    identifier = "lockout.test@example.com"
    await lockout_manager.unlock_account(identifier)

    # Initial state: not locked
    locked, _ = await lockout_manager.is_locked(identifier)
    assert locked is False

    # Record 4 failures: should not be locked yet
    for _ in range(4):
        count, now_locked = await lockout_manager.record_failed_attempt(identifier)
        assert now_locked is False

    # 5th failure: threshold reached, should be locked
    count, now_locked = await lockout_manager.record_failed_attempt(identifier)
    assert count >= 5
    assert now_locked is True

    # Verify is_locked reports True with remaining TTL
    is_locked, remaining_ttl = await lockout_manager.is_locked(identifier)
    assert is_locked is True
    assert remaining_ttl > 0

    # Manual unlock
    await lockout_manager.unlock_account(identifier)
    is_locked, _ = await lockout_manager.is_locked(identifier)
    assert is_locked is False

