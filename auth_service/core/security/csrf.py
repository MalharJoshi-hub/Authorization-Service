"""Cross-Site Request Forgery (CSRF) protection module for Auth-as-a-Service.

Implements cryptographically signed double-submit cookie patterns, signed tokens with
expiration timestamps, and constant-time token comparison to defend against side-channel attacks.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import os
import secrets
import time
from typing import Optional, Tuple

from auth_service.core.config import settings
from auth_service.core.exceptions import AuthenticationError


class CSRFError(AuthenticationError):
    """Raised when CSRF validation fails."""

    def __init__(self, message: str = "CSRF token validation failed") -> None:
        super().__init__(message=message, code="CSRF_VALIDATION_FAILED")


class CSRFProtector:
    """Provides CSRF token creation, signing, and verification utilities."""

    def __init__(
        self,
        secret_key: Optional[str] = None,
        token_lifetime_seconds: int = 3600,
        cookie_name: str = "csrf_token",
        header_name: str = "X-CSRF-Token",
    ) -> None:
        self.secret_key = (secret_key or settings.SECRET_KEY).encode("utf-8")
        self.token_lifetime_seconds = token_lifetime_seconds
        self.cookie_name = cookie_name
        self.header_name = header_name

    def generate_token(self, session_id: Optional[str] = None) -> str:
        """Generate a signed, timestamped CSRF token.

        Format: base64(random_salt:timestamp:session_id:signature)
        """
        random_bytes = secrets.token_bytes(16)
        timestamp = int(time.time())
        salt = base64.urlsafe_b64encode(random_bytes).decode("ascii").rstrip("=")
        sid = session_id or "anonymous"

        payload = f"{salt}:{timestamp}:{sid}"
        signature = self._compute_signature(payload)
        full_token = f"{payload}:{signature}"
        return base64.urlsafe_b64encode(full_token.encode("utf-8")).decode("ascii")

    def _compute_signature(self, payload: str) -> str:
        """Compute HMAC-SHA256 signature for the given payload string."""
        h = hmac.new(self.secret_key, payload.encode("utf-8"), hashlib.sha256)
        return h.hexdigest()

    def verify_token(
        self,
        token: str,
        expected_session_id: Optional[str] = None,
        max_age_seconds: Optional[int] = None,
    ) -> bool:
        """Validate a CSRF token: format, signature, timestamp freshness, and session binding.

        Raises CSRFError on invalid format or signature; returns True on success.
        """
        if not token:
            raise CSRFError("Missing CSRF token")

        try:
            # Add padding if needed for urlsafe base64
            padded = token + "=" * (-len(token) % 4)
            decoded = base64.urlsafe_b64decode(padded.encode("ascii")).decode("utf-8")
            parts = decoded.split(":")
            if len(parts) != 4:
                raise CSRFError("Malformed CSRF token structure")

            salt, timestamp_str, session_id, signature = parts
            timestamp = int(timestamp_str)
        except (ValueError, UnicodeDecodeError) as e:
            raise CSRFError(f"Invalid CSRF token encoding: {e}") from e

        # 1. Verify HMAC signature using constant-time comparison
        payload = f"{salt}:{timestamp}:{session_id}"
        expected_sig = self._compute_signature(payload)
        if not hmac.compare_digest(signature, expected_sig):
            raise CSRFError("Invalid CSRF token signature")

        # 2. Check token expiration
        max_age = max_age_seconds or self.token_lifetime_seconds
        now = int(time.time())
        if now - timestamp > max_age:
            raise CSRFError("CSRF token has expired")

        if timestamp > now + 300:
            raise CSRFError("CSRF token timestamp is in the future")

        # 3. Check session binding if requested
        if expected_session_id and session_id != expected_session_id:
            raise CSRFError("CSRF token does not match active session")

        return True

    def validate_double_submit(
        self,
        cookie_token: Optional[str],
        header_token: Optional[str],
        session_id: Optional[str] = None,
    ) -> bool:
        """Validate standard double-submit cookie scheme.

        Both cookie and header tokens must exist, match each other, and pass signature checks.
        """
        if not cookie_token or not header_token:
            raise CSRFError("Missing double-submit CSRF cookie or header")

        if not hmac.compare_digest(cookie_token, header_token):
            raise CSRFError("CSRF cookie and header values do not match")

        return self.verify_token(header_token, expected_session_id=session_id)


# Global singleton
csrf_protector = CSRFProtector()
