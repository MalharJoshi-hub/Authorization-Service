"""Multi-Factor Authentication (MFA / TOTP) Service (Layer 1 & Layer 2).

Implements RFC 6238 Time-Based One-Time Password algorithms, OTP authorization URIs,
QR code generation parameters, and single-use emergency backup recovery codes.
"""

import base64
import hashlib
import hmac
import secrets
import struct
import time
from typing import List, Tuple
from urllib.parse import quote
from auth_service.config import settings


class MFAService:
    """Provides cryptographic TOTP generation, validation, and recovery code lifecycles."""

    @staticmethod
    def generate_secret(length: int = 20) -> str:
        """Generate high-entropy Base32 secret for authenticator apps."""
        random_bytes = secrets.token_bytes(length)
        return base64.b32encode(random_bytes).decode("utf-8").replace("=", "")

    @staticmethod
    def get_totp_uri(secret: str, email: str, issuer: str = None) -> str:
        """Generate canonical 'otpauth://' URI for QR code rendering."""
        app_name = issuer or settings.APP_NAME
        clean_email = quote(email.strip())
        clean_issuer = quote(app_name.strip())
        return f"otpauth://totp/{clean_issuer}:{clean_email}?secret={secret}&issuer={clean_issuer}&algorithm=SHA1&digits=6&period=30"

    @classmethod
    def generate_totp_code(cls, secret: str, timestamp: float = None) -> str:
        """Compute 6-digit TOTP code for a given timestamp."""
        t = timestamp if timestamp is not None else time.time()
        counter = int(t // 30)

        # Pad base32 string to multiple of 8 if needed
        padding = (8 - len(secret) % 8) % 8
        padded_secret = secret + ("=" * padding)
        key = base64.b32decode(padded_secret, casefold=True)

        # Pack 64-bit integer counter in big-endian format
        msg = struct.pack(">Q", counter)
        h = hmac.new(key, msg, hashlib.sha1).digest()

        # Dynamic truncation (RFC 4226)
        offset = h[-1] & 0x0F
        code_int = struct.unpack(">I", h[offset : offset + 4])[0] & 0x7FFFFFFF
        code = code_int % 1000000
        return f"{code:06d}"

    @classmethod
    def verify_totp(cls, secret: str, code: str, window: int = 1) -> bool:
        """Verify candidate code with clock drift tolerance."""
        if not secret or not code or len(code.strip()) != 6:
            return False

        clean_code = code.strip()
        now = time.time()

        # Check current window, previous window, and next window
        for offset in range(-window, window + 1):
            expected = cls.generate_totp_code(secret, timestamp=now + (offset * 30))
            if secrets.compare_digest(expected, clean_code):
                return True
        return False

    @staticmethod
    def generate_backup_codes(count: int = 10) -> Tuple[List[str], List[str]]:
        """Generate set of single-use recovery codes.

        Returns:
            Tuple of:
              - raw_codes: Plaintext codes (e.g. '8492-4912') shown ONCE to user.
              - hashed_codes: SHA-256 digests stored in database.
        """
        raw_codes = []
        hashed_codes = []

        for _ in range(count):
            p1 = secrets.token_hex(2).upper()
            p2 = secrets.token_hex(2).upper()
            raw = f"{p1}-{p2}"
            raw_codes.append(raw)
            digest = hashlib.sha256(raw.encode("utf-8")).hexdigest()
            hashed_codes.append(digest)

        return raw_codes, hashed_codes

    @staticmethod
    def verify_and_consume_backup_code(raw_code: str, stored_hashes: List[str]) -> Tuple[bool, List[str]]:
        """Verify recovery code and return updated list of remaining code hashes."""
        if not raw_code:
            return False, stored_hashes

        target_hash = hashlib.sha256(raw_code.strip().upper().encode("utf-8")).hexdigest()

        for idx, h in enumerate(stored_hashes):
            if secrets.compare_digest(h, target_hash):
                # Code matched! Remove it from stored hashes (single-use)
                remaining = [code_hash for i, code_hash in enumerate(stored_hashes) if i != idx]
                return True, remaining

        return False, stored_hashes


mfa_service = MFAService()

