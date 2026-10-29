"""Symmetric Field Encryption & Cryptographic Utilities (Layer 1: Security Core).

Provides authenticated AES-256-GCM encryption/decryption for sensitive data at rest
(e.g., OAuth access tokens, MFA shared secrets) and PBKDF2 key derivation.
"""

import base64
import hashlib
import os
import secrets
from typing import Optional, Tuple
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from auth_service.config import settings
from auth_service.core.exceptions import ValidationError


def derive_key(secret_passphrase: str, salt: bytes, iterations: int = 100_000) -> bytes:
    """Derive 256-bit cryptographic key using PBKDF2-HMAC-SHA256."""
    return hashlib.pbkdf2_hmac(
        "sha256",
        secret_passphrase.encode("utf-8"),
        salt,
        iterations,
        dklen=32,
    )


class FieldEncryptor:
    """Authenticated AES-GCM-256 field encryption engine."""

    def __init__(self, master_secret: Optional[str] = None):
        self.secret = master_secret or settings.SECRET_KEY
        # Precompute deterministic encryption key
        salt = b"aas_field_encryption_salt_2026"
        self._key = derive_key(self.secret, salt)
        self._aesgcm = AESGCM(self._key)

    def encrypt(self, plaintext: str, associated_data: Optional[bytes] = None) -> str:
        """Encrypt plaintext string with AES-256-GCM and return Base64 payload with IV."""
        if not plaintext:
            return ""

        iv = secrets.token_bytes(12)  # 96-bit nonce
        plaintext_bytes = plaintext.encode("utf-8")
        ciphertext = self._aesgcm.encrypt(iv, plaintext_bytes, associated_data)

        # Pack IV + Ciphertext
        packed = iv + ciphertext
        return base64.b64encode(packed).decode("utf-8")

    def decrypt(self, b64_ciphertext: str, associated_data: Optional[bytes] = None) -> str:
        """Decrypt Base64 ciphertext with AES-256-GCM."""
        if not b64_ciphertext:
            return ""

        try:
            packed = base64.b64decode(b64_ciphertext.encode("utf-8"))
            if len(packed) < 28:  # 12 bytes IV + 16 bytes auth tag
                raise ValidationError("Ciphertext is too short")

            iv = packed[:12]
            ciphertext = packed[12:]
            decrypted_bytes = self._aesgcm.decrypt(iv, ciphertext, associated_data)
            return decrypted_bytes.decode("utf-8")
        except Exception as e:
            raise ValidationError(f"Failed to decrypt sensitive field: {str(e)}")


field_encryptor = FieldEncryptor()


class CryptoError(ValidationError):
    """Raised when cryptographic encryption or decryption fails."""
    pass


def encrypt_data(plaintext: str, key: bytes, associated_data: Optional[bytes] = None) -> bytes:
    """Encrypt plaintext string using 256-bit key with AES-GCM and return raw bytes."""
    aesgcm = AESGCM(key)
    iv = secrets.token_bytes(12)
    ct = aesgcm.encrypt(iv, plaintext.encode("utf-8"), associated_data)
    return iv + ct


def decrypt_data(ciphertext: bytes, key: bytes, associated_data: Optional[bytes] = None) -> str:
    """Decrypt raw bytes using 256-bit key with AES-GCM."""
    if len(ciphertext) < 28:
        raise CryptoError("Ciphertext is too short")
    aesgcm = AESGCM(key)
    iv = ciphertext[:12]
    ct = ciphertext[12:]
    try:
        decrypted = aesgcm.decrypt(iv, ct, associated_data)
        return decrypted.decode("utf-8")
    except Exception as e:
        raise CryptoError(f"Decryption failed: {str(e)}") from e

