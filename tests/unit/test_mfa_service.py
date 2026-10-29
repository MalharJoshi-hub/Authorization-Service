"""Unit Tests for RFC 6238 TOTP Engine and Emergency Recovery Codes (Phase 8)."""

from auth_service.services.mfa_service import mfa_service


def test_generate_secret_and_totp_uri():
    secret = mfa_service.generate_secret()
    assert len(secret) >= 20
    uri = mfa_service.get_totp_uri(secret, "user@example.com")
    assert uri.startswith("otpauth://totp/")
    assert secret in uri
    assert "user%40example.com" in uri


def test_generate_and_verify_totp_code():
    secret = mfa_service.generate_secret()
    code = mfa_service.generate_totp_code(secret)
    assert len(code) == 6
    assert code.isdigit()

    assert mfa_service.verify_totp(secret, code) is True
    assert mfa_service.verify_totp(secret, "000000") is False


def test_generate_and_consume_backup_codes():
    raw_codes, hashed_codes = mfa_service.generate_backup_codes(count=5)
    assert len(raw_codes) == 5
    assert len(hashed_codes) == 5

    # Consume first backup code
    first_code = raw_codes[0]
    matched, remaining = mfa_service.verify_and_consume_backup_code(first_code, hashed_codes)
    assert matched is True
    assert len(remaining) == 4

    # Reuse of same code must fail
    matched_second, remaining_second = mfa_service.verify_and_consume_backup_code(first_code, remaining)
    assert matched_second is False
    assert len(remaining_second) == 4
