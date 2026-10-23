"""MFA Backup Recovery Codes Service.

Handles secure generation, cryptographic hashing, verification, and single-use invalidation
of emergency recovery codes for multi-factor authentication fallback.
"""

from __future__ import annotations

import hashlib
import hmac
import secrets
import string
from typing import List, Optional, Set, Tuple


class BackupCodesService:
    """Service to create, hash, and consume single-use MFA backup codes."""

    DEFAULT_CODE_COUNT = 10
    CODE_LENGTH = 10
    CODE_ALPHABET = string.ascii_uppercase + string.digits
    # Exclude ambiguous characters (0, O, 1, I, L) for readability
    READABLE_ALPHABET = "23456789ABCDEFGHJKMNPQRSTUVWXYZ"

    @classmethod
    def generate_single_code(cls, length: int = CODE_LENGTH) -> str:
        """Generate a single formatted code with hyphen (e.g., 'ABC4-XYZ9')."""
        half = length // 2
        p1 = "".join(secrets.choice(cls.READABLE_ALPHABET) for _ in range(half))
        p2 = "".join(secrets.choice(cls.READABLE_ALPHABET) for _ in range(length - half))
        return f"{p1}-{p2}"

    @classmethod
    def generate_backup_codes(cls, count: int = DEFAULT_CODE_COUNT) -> Tuple[List[str], List[str]]:
        """Generate a batch of recovery codes.

        Returns:
            Tuple of (plain_codes, hashed_codes)
        """
        plain_codes: List[str] = []
        hashed_codes: List[str] = []

        for _ in range(count):
            code = cls.generate_single_code()
            plain_codes.append(code)
            hashed_codes.append(cls.hash_code(code))

        return plain_codes, hashed_codes

    @classmethod
    def normalize_code(cls, raw_code: str) -> str:
        """Normalize user input code: uppercase, remove spaces and hyphens."""
        return raw_code.strip().upper().replace(" ", "").replace("-", "")

    @classmethod
    def hash_code(cls, plain_code: str) -> str:
        """Produce a SHA-256 hash of the normalized code."""
        normalized = cls.normalize_code(plain_code)
        return hashlib.sha256(normalized.encode("utf-8")).hexdigest()

    @classmethod
    def verify_and_consume(cls, input_code: str, hashed_codes: List[str]) -> Tuple[bool, List[str]]:
        """Verify an input code against available hashed codes.

        If matched, removes the code from the list and returns (True, updated_hashed_codes).
        Otherwise returns (False, unchanged_hashed_codes).
        """
        if not input_code or not hashed_codes:
            return False, hashed_codes

        input_hash = cls.hash_code(input_code)

        matched_index: Optional[int] = None
        for i, h in enumerate(hashed_codes):
            if hmac.compare_digest(input_hash, h):
                matched_index = i
                break

        if matched_index is not None:
            updated = list(hashed_codes)
            updated.pop(matched_index)
            return True, updated

        return False, hashed_codes


# Global singleton
backup_codes_service = BackupCodesService()
