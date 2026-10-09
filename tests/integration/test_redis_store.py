"""Integration Tests for Redis Caching, Rate Limiting, and Transient Stores (Phase 8)."""

import pytest
from auth_service.storage.redis.cache import cache_service
from auth_service.storage.redis.token_store import redis_token_store
from auth_service.storage.redis.rate_limit_store import rate_limit_store


@pytest.mark.asyncio
async def test_cache_service_set_get_delete():
    key = "user_settings:123"
    payload = {"theme": "dark", "notifications": True}

    # Set
    res = await cache_service.set(key, payload, ttl_seconds=30)
    assert res is True

    # Get
    cached = await cache_service.get(key)
    assert cached == payload

    # Invalidate
    await cache_service.delete(key)
    assert await cache_service.get(key) is None


@pytest.mark.asyncio
async def test_email_verification_token_lifecycle():
    user_id = "user-verify-123"
    email = "verify.me@example.com"
    tenant_id = "tenant-001"

    token = await redis_token_store.create_email_verification_token(
        user_id=user_id,
        email=email,
        tenant_id=tenant_id,
        ttl_hours=1,
    )
    assert len(token) > 20

    # Consume token
    data = await redis_token_store.verify_and_consume_email_token(token)
    assert data is not None
    assert data["user_id"] == user_id
    assert data["email"] == email

    # Re-consumption must return None (single-use)
    assert await redis_token_store.verify_and_consume_email_token(token) is None


@pytest.mark.asyncio
async def test_password_reset_token_lifecycle():
    user_id = "user-reset-456"
    email = "reset.me@example.com"
    tenant_id = "tenant-001"

    token = await redis_token_store.create_password_reset_token(
        user_id=user_id,
        email=email,
        tenant_id=tenant_id,
        ttl_hours=1,
    )

    # Verification without consumption
    peek_data = await redis_token_store.verify_password_reset_token(token)
    assert peek_data["user_id"] == user_id

    # Consume
    consume_data = await redis_token_store.consume_password_reset_token(token)
    assert consume_data["user_id"] == user_id

    # Second consume fails
    assert await redis_token_store.consume_password_reset_token(token) is None
