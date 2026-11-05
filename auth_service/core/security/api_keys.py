"""Cryptographic API Key Management Module (Layer 1).

Generates prefixed, high-entropy machine-to-machine API keys, computes SHA-256
digests for secure storage, and verifies incoming client credentials in constant time.
"""

import hashlib
import secrets
from typing import Tuple, Optional


API_KEY_PREFIX_LIVE = "aas_live_"
API_KEY_PREFIX_TEST = "aas_test_"


def generate_api_key(is_live: bool = True) -> Tuple[str, str, str]:
    """Generate a high-entropy, prefixed API key.

    Returns:
        Tuple containing:
          - full_key: Complete raw key shown ONCE to the user (e.g. 'aas_live_d84...').
          - prefix: Key prefix for indexed lookup (first 16 chars).
          - hashed_key: SHA-256 hex digest for storage.
    """
    prefix = API_KEY_PREFIX_LIVE if is_live else API_KEY_PREFIX_TEST
    random_bytes = secrets.token_urlsafe(32)
    full_key = f"{prefix}{random_bytes}"
    short_prefix = full_key[:16]
    hashed_key = hash_api_key(full_key)

    return full_key, short_prefix, hashed_key


def hash_api_key(raw_key: str) -> str:
    """Compute SHA-256 digest of an API key for safe database storage."""
    return hashlib.sha256(raw_key.encode("utf-8")).hexdigest()


def verify_api_key(raw_key: str, stored_hash: str) -> bool:
    """Verify raw API key against stored SHA-256 hash in constant time."""
    if not raw_key or not stored_hash:
        return False
    computed = hash_api_key(raw_key)
    return secrets.compare_digest(computed, stored_hash)


def mask_api_key(raw_or_prefixed: str) -> str:
    """Mask an API key for safe UI display (e.g. 'aas_live_••••••••12ef')."""
    if len(raw_or_prefixed) < 12:
        return "••••••••"
    prefix = raw_or_prefixed[:9]
    tail = raw_or_prefixed[-4:]
    return f"{prefix}••••••••{tail}"

