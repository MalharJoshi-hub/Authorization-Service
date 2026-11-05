"""Unit Tests for AES-256-GCM Field Encryption & Decryption (Phase 8: Layer 1)."""

import pytest
from auth_service.core.security.crypto import field_encryptor
from auth_service.core.exceptions import ValidationError


def test_encrypt_and_decrypt_plaintext():
    secret_text = "super-sensitive-oauth-refresh-token-or-totp-secret"
    ciphertext = field_encryptor.encrypt(secret_text)
    assert ciphertext != secret_text
    assert len(ciphertext) > 20

    decrypted = field_encryptor.decrypt(ciphertext)
    assert decrypted == secret_text


def test_encrypt_decrypt_empty():
    assert field_encryptor.encrypt("") == ""
    assert field_encryptor.decrypt("") == ""


def test_decrypt_tampered_fails():
    ciphertext = field_encryptor.encrypt("confidential-data")
    # Mutate characters in ciphertext
    tampered = ciphertext[:-4] + "AAAA"
    with pytest.raises(ValidationError):
        field_encryptor.decrypt(tampered)

