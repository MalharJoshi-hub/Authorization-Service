"""RFC 7636 Proof Key for Code Exchange (PKCE) by OAuth Public Clients.

Implements code verifier generation, SHA-256 transformation (S256), and constant-time verification
to protect authorization codes against interception and replay attacks in native and SPA apps.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import re
import secrets
from typing import Tuple


class PKCEError(ValueError):
    """Raised when PKCE validation fails."""
    pass


class PKCEHandler:
    """Provides RFC 7636 PKCE code challenge and verifier operations."""

    # Unreserved characters per RFC 3986 section 2.3: [A-Z] / [a-z] / [0-9] / "-" / "." / "_" / "~"
    VERIFIER_PATTERN = re.compile(r"^[A-Za-z0-9\-\._~]{43,128}$")

    @classmethod
    def generate_verifier(cls, length: int = 64) -> str:
        """Generate a cryptographically random code verifier (length between 43 and 128 characters)."""
        if not (43 <= length <= 128):
            raise PKCEError("PKCE code verifier length must be between 43 and 128 characters")

        raw_bytes = secrets.token_bytes(length)
        verifier = base64.urlsafe_b64encode(raw_bytes).decode("ascii").rstrip("=")
        return verifier[:length]

    @classmethod
    def create_s256_challenge(cls, verifier: str) -> str:
        """Create an S256 code challenge from a code verifier: BASE64URL-ENCODE(SHA256(ASCII(code_verifier)))."""
        if not cls.validate_verifier_format(verifier):
            raise PKCEError("Invalid code verifier format or length")

        digest = hashlib.sha256(verifier.encode("ascii")).digest()
        challenge = base64.urlsafe_b64encode(digest).decode("ascii").rstrip("=")
        return challenge

    @classmethod
    def validate_verifier_format(cls, verifier: str) -> bool:
        """Verify that code verifier satisfies character set and length constraints."""
        if not verifier or len(verifier) < 43 or len(verifier) > 128:
            return False
        return bool(cls.VERIFIER_PATTERN.match(verifier))

    @classmethod
    def verify_challenge(cls, verifier: str, challenge: str, method: str = "S256") -> bool:
        """Verify that a code verifier matches the stored code challenge."""
        if method == "plain":
            # RFC 7636 recommends S256, but plain is permitted if client is incapable
            return hmac.compare_digest(verifier, challenge)

        if method == "S256":
            try:
                computed_challenge = cls.create_s256_challenge(verifier)
                return hmac.compare_digest(computed_challenge, challenge)
            except PKCEError:
                return False

        raise PKCEError(f"Unsupported PKCE code_challenge_method: {method}")


pkce_handler = PKCEHandler()

