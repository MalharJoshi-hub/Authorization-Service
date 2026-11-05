"""Unit Tests for Traffic Control & Rate Limiting Algorithms (Phase 8: Layer 1)."""

import time
from auth_service.core.security.rate_limit_strategies import (
    TokenBucketLimiter,
    LeakyBucketLimiter,
    FixedWindowLimiter,
)


def test_token_bucket_limiter():
    limiter = TokenBucketLimiter(capacity=3, refill_rate_per_sec=1.0)
    assert limiter.allow_request() is True
    assert limiter.allow_request() is True
    assert limiter.allow_request() is True
    # Capacity exhausted
    assert limiter.allow_request() is False


def test_leaky_bucket_limiter():
    limiter = LeakyBucketLimiter(capacity=2, leak_rate_per_sec=1.0)
    assert limiter.add_request() is True
    assert limiter.add_request() is True
    # Bucket full
    assert limiter.add_request() is False


def test_fixed_window_limiter():
    limiter = FixedWindowLimiter(limit=2, window_seconds=60)
    key = "client-alpha"
    assert limiter.allow(key) is True
    assert limiter.allow(key) is True
    # Exceeded for this window
    assert limiter.allow(key) is False
    # Different key is permitted
    assert limiter.allow("client-beta") is True

