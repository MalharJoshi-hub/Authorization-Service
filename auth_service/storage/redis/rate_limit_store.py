"""Rate Limit Redis Storage Adapter (Layer 4).

Wraps low-level sorted set rate limit counter queries and maintenance.
"""

from typing import List, Tuple
from auth_service.storage.redis.client import get_redis_client


class RateLimitStore:
    """Manages Redis keys for rate limiting."""

    @staticmethod
    async def reset_identifier(identifier: str) -> bool:
        """Reset rate limit counter for a specific identifier."""
        redis = await get_redis_client()
        key = f"ratelimit:{identifier}"
        await redis.delete(key)
        return True

    @staticmethod
    async def get_current_count(identifier: str) -> int:
        """Fetch current request count for key."""
        redis = await get_redis_client()
        key = f"ratelimit:{identifier}"
        return await redis.zcard(key)


rate_limit_store = RateLimitStore()
