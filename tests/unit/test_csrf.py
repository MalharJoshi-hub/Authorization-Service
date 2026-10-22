"""Unit tests for CSRF token protection and double-submit cookie verification."""

import time
import pytest
from auth_service.core.security.csrf import CSRFProtector, CSRFError


def test_csrf_generate_and_verify():
    protector = CSRFProtector(secret_key="test-secret-key-for-csrf", token_lifetime_seconds=3600)
    token = protector.generate_token(session_id="sess-12345")
    assert token is not None
    assert len(token) > 20

    is_valid = protector.verify_token(token, expected_session_id="sess-12345")
    assert is_valid is True


def test_csrf_tampered_token_fails():
    protector = CSRFProtector(secret_key="test-secret-key-for-csrf")
    token = protector.generate_token(session_id="sess-12345")
    tampered = token[:-4] + "AAAA"

    with pytest.raises(CSRFError):
        protector.verify_token(tampered, expected_session_id="sess-12345")


def test_csrf_session_mismatch_fails():
    protector = CSRFProtector(secret_key="test-secret-key-for-csrf")
    token = protector.generate_token(session_id="sess-alice")

    with pytest.raises(CSRFError):
        protector.verify_token(token, expected_session_id="sess-bob")


def test_csrf_expired_token_fails():
    protector = CSRFProtector(secret_key="test-secret-key-for-csrf", token_lifetime_seconds=1)
    token = protector.generate_token(session_id="sess-12345")

    # Verify with 0 max age to simulate immediate expiration
    with pytest.raises(CSRFError):
        protector.verify_token(token, max_age_seconds=-1)


def test_csrf_double_submit_success():
    protector = CSRFProtector(secret_key="test-secret-key-for-csrf")
    token = protector.generate_token(session_id="sess-xyz")

    assert protector.validate_double_submit(cookie_token=token, header_token=token, session_id="sess-xyz") is True


def test_csrf_double_submit_mismatch_fails():
    protector = CSRFProtector(secret_key="test-secret-key-for-csrf")
    token1 = protector.generate_token(session_id="sess-xyz")
    token2 = protector.generate_token(session_id="sess-xyz")

    with pytest.raises(CSRFError):
        protector.validate_double_submit(cookie_token=token1, header_token=token2)


def test_csrf_missing_tokens_fail():
    protector = CSRFProtector()
    with pytest.raises(CSRFError):
        protector.validate_double_submit(cookie_token=None, header_token="xyz")

    with pytest.raises(CSRFError):
        protector.validate_double_submit(cookie_token="abc", header_token=None)

    with pytest.raises(CSRFError):
        protector.verify_token("")
