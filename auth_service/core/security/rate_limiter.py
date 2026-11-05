"""Sliding Window Rate Limiter Engine (Layer 1).

Implements a precision sliding-window rate limiting algorithm using Redis sorted sets
to eliminate boundary burst anomalies and enforce strict API throttling quotas.
"""

import time
import uuid
from typing import Optional, Tuple
from fastapi import Request
from auth_service.config import settings
from auth_service.core.exceptions import RateLimitExceededError
from auth_service.core.logger import logger
from auth_service.storage.redis.client import get_redis_client


class RateLimiter:
    """Sliding-window rate limiter utilizing Redis sorted sets."""

    def __init__(self, default_limit: int = 100, window_seconds: int = 60):
        self.default_limit = default_limit
        self.window_seconds = window_seconds

    async def check(
        self,
        identifier: str,
        limit: Optional[int] = None,
        window: Optional[int] = None,
    ) -> Tuple[bool, int, int, int]:
        """Check if an identifier has exceeded quota within the sliding window.

        Args:
            identifier: Rate limit key (e.g., 'ip:192.168.1.1:endpoint:/auth/login').
            limit: Maximum requests permitted within the window (defaults to self.default_limit).
            window: Time window duration in seconds (defaults to self.window_seconds).

        Returns:
            Tuple of:
              - is_exceeded: True if rate limit is exceeded, False otherwise.
              - remaining: Number of remaining allowed requests.
              - reset_seconds: Seconds until current sliding window resets.
              - limit: Total limit applied.
        """
        if not settings.RATE_LIMIT_ENABLED:
            return False, 9999, 0, 9999

        actual_limit = limit or self.default_limit
        actual_window = window or self.window_seconds

        now = time.time()
        window_start = now - actual_window
        key = f"ratelimit:{identifier}"

        redis = await get_redis_client()
        try:
            # 1. Remove entries older than sliding window
            await redis.zremrangebyscore(key, 0, window_start)

            # 2. Count current entries in window
            current_count = await redis.zcard(key)

            if current_count >= actual_limit:
                reset_seconds = actual_window
                return True, 0, reset_seconds, actual_limit

            # 3. Add current request with timestamp as score
            member_id = f"{now}:{uuid.uuid4().hex[:8]}"
            await redis.zadd(key, {member_id: now})

            # 4. Set TTL on set to auto-cleanup inactive keys
            await redis.expire(key, actual_window + 5)

            remaining = max(0, actual_limit - (current_count + 1))
            return False, remaining, actual_window, actual_limit

        except Exception as e:
            logger.error(f"Rate limiter execution error: {e}")
            # Fail open for resilience if rate limiting cache encounters unexpected issue
            return False, actual_limit, actual_window, actual_limit


rate_limiter = RateLimiter(default_limit=settings.RATE_LIMIT_DEFAULT_PER_MINUTE)


def get_client_ip(request: Request) -> str:
    """Extract client IP handling reverse proxy forwarded headers."""
    forwarded = request.headers.get("X-Forwarded-For")
    if forwarded:
        return forwarded.split(",")[0].strip()
    real_ip = request.headers.get("X-Real-IP")
    if real_ip:
        return real_ip.strip()
    return request.client.host if request.client else "127.0.0.1"


async def check_rate_limit(
    request: Request,
    endpoint_tag: str,
    limit: int,
    window_seconds: int = 60,
) -> None:
    """FastAPI dependency helper to enforce rate limiting on specific endpoints."""
    ip = get_client_ip(request)
    identifier = f"{ip}:{endpoint_tag}"

    is_exceeded, remaining, reset_time, total = await rate_limiter.check(
        identifier=identifier,
        limit=limit,
        window=window_seconds,
    )

    # Attach headers to request state for response middleware injection
    request.state.rate_limit_limit = total
    request.state.rate_limit_remaining = remaining
    request.state.rate_limit_reset = reset_time

    if is_exceeded:
        raise RateLimitExceededError(
            message=f"Too many requests for {endpoint_tag}. Limit: {limit}/{window_seconds}s. Try again in {reset_time}s.",
            retry_after=reset_time,
        )

