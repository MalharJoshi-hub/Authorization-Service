"""Unit Tests for Distributed Token Blacklist Operations (Phase 8: Layer 1)."""

import pytest
from auth_service.core.security.token_blacklist import token_blacklist


@pytest.mark.asyncio
async def test_blacklist_and_check_token():
    jti = "test-jti-12345"
    assert await token_blacklist.is_blacklisted(jti) is False

    # Blacklist for 60 seconds
    res = await token_blacklist.blacklist_token(jti, ttl_seconds=60)
    assert res is True
    assert await token_blacklist.is_blacklisted(jti) is True


@pytest.mark.asyncio
async def test_blacklist_empty_or_expired_jti():
    assert await token_blacklist.blacklist_token("", 60) is False
    assert await token_blacklist.is_blacklisted(None) is False
    assert await token_blacklist.is_blacklisted("") is False
    # Negative TTL is effectively expired
    assert await token_blacklist.blacklist_token("jti-zero-ttl", ttl_seconds=0) is True

