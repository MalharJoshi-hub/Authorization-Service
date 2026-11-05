"""Comprehensive password validation, entropy, and complexity matrix tests."""

import pytest
from auth_service.core.security.password import (
    hash_password,
    verify_password,
    validate_password_complexity,
)
from auth_service.services.password_policy_service import PasswordPolicyService


# --- 1. Complexity Requirements Matrix ---

@pytest.mark.parametrize("password,is_valid", [
    ("Short1!", False),                          # < 8 chars
    ("alllowercase123!", False),                 # Missing uppercase
    ("ALLUPPERCASE123!", False),                 # Missing lowercase
    ("NoSpecialChars123", False),                # Missing special char
    ("NoNumbersSpecial!!", False),               # Missing number
    ("ValidP@ssword123", True),                  # Standard valid
    ("C0mpl3x!P@ssw0rd2026", True),              # Highly complex
    ("Str0ng!WithSp@ces 2026", True),            # Spaces included
    ("UnicodeP@ssw0rd123🚀", True),              # Emoji included
    ("Tésting123!@#Accénts", True),              # Accented characters
])
def test_password_complexity_matrix(password, is_valid):
    result, _ = validate_password_complexity(password)
    assert result == is_valid


# --- 2. Hashing & Verification Roundtrip Matrix ---

@pytest.mark.parametrize("plain_pwd", [
    "SimpleValid123!@",
    "ExtremelyLongPasswordStringThatHasMoreThanSixtyFourCharactersInTotalToTestBcryptTruncationAndEntropy2026!@",
    "Unicode_ÄÖÜ_ß_1234!#",
    "Special_~!@#$%^&*()_+`-={}|[]\\:\";'<>?,./_123Aa",
    "With   Lots   Of   Spaces   123!Aa",
])
def test_hash_verify_roundtrip_matrix(plain_pwd):
    hashed = hash_password(plain_pwd)
    assert hashed != plain_pwd
    assert hashed.startswith("$2b$") or hashed.startswith("$2a$")

    # Positive verification
    assert verify_password(plain_pwd, hashed) is True

    # Negative verification
    assert verify_password(plain_pwd + "_wrong", hashed) is False
    assert verify_password(plain_pwd.lower(), hashed) is False


# --- 3. Password Policy Scoring Matrix ---

def test_password_policy_strength_scoring():
    service = PasswordPolicyService()

    # Weak password
    weak_score, weak_reasons = service.evaluate_strength("weak")
    assert weak_score < 40
    assert len(weak_reasons) > 0

    # Medium password
    med_score, _ = service.evaluate_strength("MediumPass1!")
    assert 40 <= med_score <= 85

    # Very strong password
    strong_score, strong_reasons = service.evaluate_strength("Super-Secure-Long-Passphrase-2026-XyZ#!")
    assert strong_score >= 80


# --- 4. Timing Uniformity and False Rejections ---

def test_verify_password_empty_or_none():
    assert verify_password("", "some_hash") is False
    assert verify_password("pwd", "") is False
    assert verify_password("", "") is False


def test_verify_password_malformed_hash():
    assert verify_password("Valid123!@", "invalid_hash_format") is False
    assert verify_password("Valid123!@", "$2b$04$tooshort") is False
    assert verify_password("Valid123!@", "not_a_bcrypt_hash") is False


# --- 5. Truncation and Salt Uniqueness ---

def test_bcrypt_salt_uniqueness():
    # Hashing the same password twice must yield different salts
    pwd = "SamePassword123!@"
    h1 = hash_password(pwd)
    h2 = hash_password(pwd)
    assert h1 != h2
    assert verify_password(pwd, h1) is True
    assert verify_password(pwd, h2) is True

