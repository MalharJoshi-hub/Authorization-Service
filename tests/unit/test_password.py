"""Unit Tests for Password Hashing and Complexity Policies (Phase 8: Layer 1)."""

import pytest
from auth_service.core.security.password import (
    hash_password,
    verify_password,
    validate_password_complexity,
    generate_secure_password,
)
from auth_service.core.exceptions import ValidationError


def test_hash_password_generates_valid_bcrypt_hash():
    password = "SecurePassword123!@"
    hashed = hash_password(password, rounds=10)
    assert hashed.startswith("$2b$") or hashed.startswith("$2a$")
    assert hashed != password


def test_verify_password_matches_correct_hash():
    password = "CorrectHorseBatteryStaple!1"
    hashed = hash_password(password, rounds=10)
    assert verify_password(password, hashed) is True
    assert verify_password("WrongPassword123!@", hashed) is False


def test_verify_password_handles_empty_and_malformed():
    assert verify_password("", "some_hash") is False
    assert verify_password("pass", "") is False
    assert verify_password("pass", "malformed_hash_without_bcrypt_prefix") is False


def test_hash_password_rejects_empty():
    with pytest.raises(ValidationError):
        hash_password("")


def test_password_complexity_min_length():
    valid, msg = validate_password_complexity("Short1!")
    assert valid is False
    assert "at least 8 characters" in msg


def test_password_complexity_uppercase_required():
    valid, msg = validate_password_complexity("nouppercase123!@")
    assert valid is False
    assert "uppercase" in msg


def test_password_complexity_lowercase_required():
    valid, msg = validate_password_complexity("NOLOWERCASE123!@")
    assert valid is False
    assert "lowercase" in msg


def test_password_complexity_digit_required():
    valid, msg = validate_password_complexity("NoDigitsHere!@#")
    assert valid is False
    assert "digit" in msg


def test_password_complexity_special_char_required():
    valid, msg = validate_password_complexity("NoSpecialChars1234")
    assert valid is False
    assert "special character" in msg


def test_password_complexity_valid_password():
    valid, msg = validate_password_complexity("CompliantP@ssw0rd2026!")
    assert valid is True
    assert msg == ""


def test_generate_secure_password():
    for _ in range(5):
        pwd = generate_secure_password(length=16)
        assert len(pwd) >= 16
        valid, _ = validate_password_complexity(pwd)
        assert valid is True
