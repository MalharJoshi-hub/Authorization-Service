"""Unit tests for RFC 7636 Proof Key for Code Exchange (PKCE)."""

import pytest
from auth_service.core.security.pkce import PKCEHandler, PKCEError, pkce_handler


def test_generate_verifier_valid_lengths():
    v1 = PKCEHandler.generate_verifier(43)
    assert len(v1) == 43
    assert PKCEHandler.validate_verifier_format(v1) is True

    v2 = PKCEHandler.generate_verifier(128)
    assert len(v2) == 128
    assert PKCEHandler.validate_verifier_format(v2) is True


def test_generate_verifier_invalid_length_raises():
    with pytest.raises(PKCEError):
        PKCEHandler.generate_verifier(42)

    with pytest.raises(PKCEError):
        PKCEHandler.generate_verifier(129)


def test_create_s256_challenge():
    verifier = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"
    challenge = PKCEHandler.create_s256_challenge(verifier)
    assert challenge is not None
    assert len(challenge) == 43  # Base64URL-encoded SHA-256 without padding is 43 chars


def test_verify_challenge_s256_success():
    verifier = PKCEHandler.generate_verifier(64)
    challenge = PKCEHandler.create_s256_challenge(verifier)

    assert PKCEHandler.verify_challenge(verifier, challenge, method="S256") is True


def test_verify_challenge_s256_tampered_fails():
    verifier = PKCEHandler.generate_verifier(64)
    challenge = PKCEHandler.create_s256_challenge(verifier)

    wrong_verifier = PKCEHandler.generate_verifier(64)
    assert PKCEHandler.verify_challenge(wrong_verifier, challenge, method="S256") is False


def test_verify_challenge_plain():
    verifier = "plain-code-verifier-string-length-over-43-chars-long"
    assert PKCEHandler.verify_challenge(verifier, verifier, method="plain") is True
    assert PKCEHandler.verify_challenge(verifier, "different", method="plain") is False


def test_verify_challenge_invalid_method():
    with pytest.raises(PKCEError):
        PKCEHandler.verify_challenge("verifier", "challenge", method="unsupported_method")

