"""Unit tests for breached password checking system."""

import pytest
from auth_service.core.security.pwned_passwords import PwnedPasswordChecker, BreachedPasswordError


@pytest.mark.asyncio
async def test_common_offline_passwords_rejected():
    checker = PwnedPasswordChecker(enable_remote_check=False)
    assert checker.is_common_offline("password") is True
    assert checker.is_common_offline("password123") is True
    assert checker.is_common_offline("admin123") is True
    assert checker.is_common_offline("ComplexUniqueTr!0n2026") is False

    with pytest.raises(BreachedPasswordError):
        await checker.check_password("123456")


@pytest.mark.asyncio
async def test_safe_password_passes_offline():
    checker = PwnedPasswordChecker(enable_remote_check=False)
    res = await checker.check_password("SuperSecretPassphrase-2026-XyZ#")
    assert res == 0


@pytest.mark.asyncio
async def test_remote_mock_cache():
    checker = PwnedPasswordChecker(enable_remote_check=True)
    # Populate mock cache for a known prefix
    import hashlib
    test_pwd = "PwnedTestPassword123"
    sha1_hash = hashlib.sha1(test_pwd.encode("utf-8")).hexdigest().upper()
    prefix = sha1_hash[:5]
    suffix = sha1_hash[5:]

    import time
    checker._cache[prefix] = (time.time(), {suffix: 42})

    with pytest.raises(BreachedPasswordError) as exc_info:
        await checker.check_password(test_pwd)

    assert exc_info.value.breach_count == 42


@pytest.mark.asyncio
async def test_remote_failure_graceful_fallback():
    checker = PwnedPasswordChecker(enable_remote_check=True, api_timeout=0.001)
    # Non-common password with immediate timeout fallback
    res = await checker.check_password("SafeRandomString-99881122")
    assert res == 0
