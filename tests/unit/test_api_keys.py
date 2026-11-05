"""Unit Tests for Machine API Key Primitives (Phase 8: Layer 1)."""

from auth_service.core.security.api_keys import (
    generate_api_key,
    hash_api_key,
    verify_api_key,
    mask_api_key,
    API_KEY_PREFIX_LIVE,
    API_KEY_PREFIX_TEST,
)


def test_generate_live_api_key():
    full_key, prefix, key_hash = generate_api_key(is_live=True)
    assert full_key.startswith(API_KEY_PREFIX_LIVE)
    assert prefix == full_key[:16]
    assert len(key_hash) == 64  # SHA-256 hex string


def test_generate_test_api_key():
    full_key, prefix, key_hash = generate_api_key(is_live=False)
    assert full_key.startswith(API_KEY_PREFIX_TEST)
    assert prefix == full_key[:16]


def test_verify_api_key():
    full_key, _, key_hash = generate_api_key()
    assert verify_api_key(full_key, key_hash) is True
    assert verify_api_key("wrong_key_aas_live_1234", key_hash) is False
    assert verify_api_key("", key_hash) is False
    assert verify_api_key(full_key, "") is False


def test_mask_api_key():
    full_key, prefix, _ = generate_api_key()
    masked = mask_api_key(full_key)
    assert masked.startswith(API_KEY_PREFIX_LIVE)
    assert "••••••••" in masked
    assert masked[-4:] == full_key[-4:]
    assert mask_api_key("short") == "••••••••"

