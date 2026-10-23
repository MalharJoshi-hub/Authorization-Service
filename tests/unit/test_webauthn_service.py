"""Unit tests for WebAuthn and FIDO2 Passkeys service."""

import pytest
from auth_service.services.mfa_webauthn_service import WebAuthnService


def test_create_registration_options():
    service = WebAuthnService(rp_id="example.com", rp_name="Example App")
    options = service.create_registration_options(
        user_id="user-12345",
        username="alice@example.com",
        display_name="Alice Smith",
    )

    assert "challenge" in options
    assert options["rp"]["id"] == "example.com"
    assert options["user"]["name"] == "alice@example.com"
    assert len(options["pubKeyCredParams"]) >= 2
    assert options["authenticatorSelection"]["residentKey"] == "preferred"


def test_create_authentication_options():
    service = WebAuthnService(rp_id="example.com")
    options = service.create_authentication_options(
        user_id="user-12345",
        allowed_credential_ids=["cred_id_1", "cred_id_2"],
    )

    assert "challenge" in options
    assert options["rpId"] == "example.com"
    assert len(options["allowCredentials"]) == 2


def test_verify_challenge_consumption_and_expiry():
    service = WebAuthnService()
    options = service.create_registration_options(user_id="u1", username="u1")
    challenge_token = options["challenge"]

    # Verify and consume
    item = service.verify_challenge(challenge_token, expected_type="registration")
    assert item is not None
    assert item.user_id == "u1"

    # Consuming again fails (replay protection)
    item_second = service.verify_challenge(challenge_token, expected_type="registration")
    assert item_second is None


def test_verify_assertion_counter_anti_cloning():
    service = WebAuthnService()

    # Normal increment
    assert service.verify_assertion_counter(stored_counter=10, presented_counter=11) is True

    # Replay or cloned authenticator (counter hasn't progressed)
    assert service.verify_assertion_counter(stored_counter=10, presented_counter=10) is False
    assert service.verify_assertion_counter(stored_counter=10, presented_counter=9) is False
