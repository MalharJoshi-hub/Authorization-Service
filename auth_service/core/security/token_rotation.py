"""Refresh Token Rotation & Cryptographic Reuse Attack Detection (Layer 1).

Implements single-use refresh token rotation according to OAuth 2.0 Security BCP.
Detects token theft attempts by monitoring reuse of previously rotated tokens.
"""

import hashlib
import secrets
from datetime import datetime, timezone
from typing import Optional, Tuple
from auth_service.core.exceptions import TokenReuseDetectedError, AuthenticationError
from auth_service.core.logger import logger


def hash_token(raw_token: str) -> str:
    """Generate SHA-256 digest of a raw token for secure database storage."""
    return hashlib.sha256(raw_token.encode("utf-8")).hexdigest()


class TokenRotationManager:
    """Orchestrates token rotation, parent lineage tracking, and theft detection."""

    def __init__(self):
        self._families = {}

    async def record_token_issue(self, family_id: str, token: str) -> None:
        """Register newly issued token for family."""
        if family_id not in self._families:
            self._families[family_id] = {"active": token, "history": set()}
        else:
            self._families[family_id]["active"] = token

    async def validate_and_rotate(self, family_id: str, current_token: str, new_token: str) -> bool:
        """Validate single-use refresh token presentation and rotate to new child."""
        fam = self._families.get(family_id)
        if not fam:
            return False
        if current_token in fam["history"]:
            # Token reuse detected! Revoke whole family
            self._families.pop(family_id, None)
            return False
        if current_token != fam["active"]:
            return False
        fam["history"].add(current_token)
        fam["active"] = new_token
        return True

    @staticmethod
    def generate_token_entropy() -> str:
        """Generate high-entropy random hex token for opaque identifiers."""
        return secrets.token_hex(32)

    @staticmethod
    def verify_token_hash(raw_token: str, stored_hash: str) -> bool:
        """Constant-time verification of token hash."""
        candidate_hash = hash_token(raw_token)
        return secrets.compare_digest(candidate_hash, stored_hash)

    @staticmethod
    def check_reuse_violation(is_revoked: bool, was_rotated: bool) -> None:
        """Evaluate if presentation of a token constitutes a reuse attack.

        If a token was already marked as rotated or revoked and is presented again,
        an attacker has likely captured a copy of the token.

        Raises:
            TokenReuseDetectedError: If reuse violation is detected.
        """
        if is_revoked or was_rotated:
            logger.critical("Security Alert: Refresh token reuse detected! Invalidating token family.")
            raise TokenReuseDetectedError(
                "Refresh token reuse detected. All active sessions in this family have been terminated."
            )


token_rotation_manager = TokenRotationManager()
