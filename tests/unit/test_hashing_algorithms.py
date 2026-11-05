"""Unit tests for multi-algorithm password hashing engine."""

import pytest
from auth_service.core.security.hashing_algorithms import MultiAlgorithmHasher, HashAlgorithm


def test_hasher_bcrypt():
    hasher = MultiAlgorithmHasher(preferred_algorithm=HashAlgorithm.BCRYPT)
    pwd = "SecureP@ssword2026!"
    hashed = hasher.hash(pwd, algorithm=HashAlgorithm.BCRYPT)

    assert hashed.startswith("$2b$")
    assert hasher.identify_algorithm(hashed) == HashAlgorithm.BCRYPT
    assert hasher.verify(pwd, hashed) is True
    assert hasher.verify("WrongPassword", hashed) is False


def test_hasher_pbkdf2():
    hasher = MultiAlgorithmHasher()
    pwd = "Pbkdf2Password123!"
    hashed = hasher.hash(pwd, algorithm=HashAlgorithm.PBKDF2_SHA256)

    assert hashed.startswith("pbkdf2_sha256$")
    assert hasher.identify_algorithm(hashed) == HashAlgorithm.PBKDF2_SHA256
    assert hasher.verify(pwd, hashed) is True
    assert hasher.verify("InvalidPwd", hashed) is False


def test_hasher_scrypt():
    hasher = MultiAlgorithmHasher()
    pwd = "ScryptPassw0rd#!"
    hashed = hasher.hash(pwd, algorithm=HashAlgorithm.SCRYPT)

    assert hashed.startswith("scrypt$")
    assert hasher.identify_algorithm(hashed) == HashAlgorithm.SCRYPT
    assert hasher.verify(pwd, hashed) is True
    assert hasher.verify("Mismatch", hashed) is False


def test_hasher_needs_rehash_algorithm_change():
    hasher = MultiAlgorithmHasher(preferred_algorithm=HashAlgorithm.BCRYPT)
    pbkdf2_hash = hasher.hash("test", algorithm=HashAlgorithm.PBKDF2_SHA256)

    # Hash was generated with PBKDF2, but preferred is BCRYPT -> needs rehash
    assert hasher.needs_rehash(pbkdf2_hash) is True


def test_hasher_needs_rehash_low_rounds():
    hasher = MultiAlgorithmHasher(preferred_algorithm=HashAlgorithm.BCRYPT)
    # Synthetic low-round bcrypt hash
    low_round_hash = "$2b$04$20characterrandomsalt12345678901234567890"
    assert hasher.needs_rehash(low_round_hash) is True


def test_hasher_unsupported_algorithm():
    hasher = MultiAlgorithmHasher()
    with pytest.raises(ValueError):
        hasher.hash("pwd", algorithm="unsupported_algo")


def test_identify_unknown_algorithm():
    hasher = MultiAlgorithmHasher()
    assert hasher.identify_algorithm("plain_text_md5_hash") == "unknown"
    assert hasher.verify("pwd", "unknown_format") is False

