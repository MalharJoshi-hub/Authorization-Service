"""Unit Tests for Sliding-Window Rate Limiting Algorithm (Phase 8: Layer 1)."""

import pytest
from auth_service.config import settings
from auth_service.core.security.rate_limiter import RateLimiter


@pytest.mark.asyncio
async def test_rate_limiter_allows_under_quota():
    prev = settings.RATE_LIMIT_ENABLED
    settings.RATE_LIMIT_ENABLED = True
    try:
        limiter = RateLimiter(default_limit=5, window_seconds=60)
        key = "unit-test-ip-1"

        for i in range(5):
            exceeded, remaining, reset_secs, limit = await limiter.check(key, limit=5, window=60)
            assert exceeded is False
            assert limit == 5
            assert remaining == 5 - (i + 1)
    finally:
        settings.RATE_LIMIT_ENABLED = prev


@pytest.mark.asyncio
async def test_rate_limiter_blocks_over_quota():
    prev = settings.RATE_LIMIT_ENABLED
    settings.RATE_LIMIT_ENABLED = True
    try:
        limiter = RateLimiter(default_limit=3, window_seconds=60)
        key = "unit-test-ip-blocked"

        # Consume 3 requests
        for _ in range(3):
            await limiter.check(key, limit=3, window=60)

        # 4th request must be blocked
        exceeded, remaining, reset_secs, limit = await limiter.check(key, limit=3, window=60)
        assert exceeded is True
        assert remaining == 0
        assert reset_secs > 0
    finally:
        settings.RATE_LIMIT_ENABLED = prev
