"""WebAuthn / FIDO2 Passkeys Hardware Authentication Service.

Implements W3C Web Authentication specification primitives:
- Challenge generation and ephemeral session storage
- Relying Party (RP) configuration
- Attestation and assertion challenge verification
- Credential public key registration and signature counter anti-cloning checks
"""

from __future__ import annotations

import base64
import os
import secrets
import time
from typing import Any, Dict, List, Optional, Tuple

from auth_service.core.config import settings
from auth_service.core.logger import get_logger

logger = get_logger("auth_service.services.webauthn")


class WebAuthnChallenge:
    """Represents an active registration or assertion challenge."""

    def __init__(self, challenge_str: str, user_id: str, challenge_type: str, ttl_seconds: int = 300) -> None:
        self.challenge = challenge_str
        self.user_id = user_id
        self.challenge_type = challenge_type
        self.expires_at = time.time() + ttl_seconds

    def is_expired(self) -> bool:
        """Check if challenge exceeded validity window."""
        return time.time() > self.expires_at


class WebAuthnService:
    """Manages FIDO2 Passkey ceremonies and credential verification."""

    COSE_ALGORITHMS = {
        -7: "ES256",   # ECDSA w/ SHA-256
        -257: "RS256", # RSASSA-PKCS1-v1_5 w/ SHA-256
        -8: "EdDSA",   # Ed25519
    }

    def __init__(
        self,
        rp_id: Optional[str] = None,
        rp_name: Optional[str] = None,
        origin: Optional[str] = None,
    ) -> None:
        self.rp_id = rp_id or "localhost"
        self.rp_name = rp_name or "Auth Service"
        self.origin = origin or f"https://{self.rp_id}"
        # In-memory challenge store: challenge_id -> WebAuthnChallenge
        self._challenges: Dict[str, WebAuthnChallenge] = {}

    def generate_challenge_token(self) -> str:
        """Generate a cryptographically random 32-byte base64url challenge string."""
        raw = secrets.token_bytes(32)
        return base64.urlsafe_b64encode(raw).decode("ascii").rstrip("=")

    def create_registration_options(
        self,
        user_id: str,
        username: str,
        display_name: Optional[str] = None,
        existing_credential_ids: Optional[List[str]] = None,
    ) -> Dict[str, Any]:
        """Generate PublicKeyCredentialCreationOptions dictionary for navigator.credentials.create()."""
        challenge = self.generate_challenge_token()
        self._challenges[challenge] = WebAuthnChallenge(
            challenge_str=challenge,
            user_id=user_id,
            challenge_type="registration",
        )

        user_handle = base64.urlsafe_b64encode(user_id.encode("utf-8")).decode("ascii").rstrip("=")

        options = {
            "challenge": challenge,
            "rp": {
                "name": self.rp_name,
                "id": self.rp_id,
            },
            "user": {
                "id": user_handle,
                "name": username,
                "displayName": display_name or username,
            },
            "pubKeyCredParams": [
                {"type": "public-key", "alg": -7},    # ES256
                {"type": "public-key", "alg": -257},  # RS256
                {"type": "public-key", "alg": -8},    # EdDSA
            ],
            "authenticatorSelection": {
                "authenticatorAttachment": "platform",
                "residentKey": "preferred",
                "userVerification": "preferred",
            },
            "timeout": 60000,
            "attestation": "none",
            "excludeCredentials": [
                {"id": cid, "type": "public-key"} for cid in (existing_credential_ids or [])
            ],
        }
        return options

    def create_authentication_options(
        self,
        user_id: Optional[str] = None,
        allowed_credential_ids: Optional[List[str]] = None,
    ) -> Dict[str, Any]:
        """Generate PublicKeyCredentialRequestOptions for navigator.credentials.get()."""
        challenge = self.generate_challenge_token()
        self._challenges[challenge] = WebAuthnChallenge(
            challenge_str=challenge,
            user_id=user_id or "anonymous",
            challenge_type="authentication",
        )

        options: Dict[str, Any] = {
            "challenge": challenge,
            "timeout": 60000,
            "rpId": self.rp_id,
            "userVerification": "preferred",
        }

        if allowed_credential_ids:
            options["allowCredentials"] = [
                {"id": cid, "type": "public-key"} for cid in allowed_credential_ids
            ]

        return options

    def verify_challenge(self, challenge: str, expected_type: str) -> Optional[WebAuthnChallenge]:
        """Validate challenge freshness and consumption."""
        item = self._challenges.pop(challenge, None)
        if not item:
            logger.warning("WebAuthn challenge not found or already consumed: %s", challenge)
            return None

        if item.is_expired():
            logger.warning("WebAuthn challenge has expired: %s", challenge)
            return None

        if item.challenge_type != expected_type:
            logger.warning(
                "WebAuthn challenge type mismatch. Expected %s, got %s",
                expected_type,
                item.challenge_type,
            )
            return None

        return item

    def verify_assertion_counter(self, stored_counter: int, presented_counter: int) -> bool:
        """Verify signature counter to prevent cloned authenticator attacks.

        If presented_counter is less than or equal to stored_counter (and stored_counter > 0),
        an authenticator clone or replay is suspected.
        """
        if stored_counter > 0 and presented_counter <= stored_counter:
            logger.error(
                "Authenticator clone suspected! Stored counter=%s >= presented=%s",
                stored_counter,
                presented_counter,
            )
            return False
        return True


# Global singleton
webauthn_service = WebAuthnService()
