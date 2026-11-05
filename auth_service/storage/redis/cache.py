"""Redis Caching Layer (Layer 4).

Provides low-latency distributed caching with automatic TTL eviction for
frequently read user records, permissions, and tenant metadata.
"""

import json
from typing import Any, Optional
from auth_service.core.logger import logger
from auth_service.storage.redis.client import get_redis_client


class CacheService:
    """Distributed cache interface."""

    PREFIX = "cache:"

    @classmethod
    async def get(cls, key: str) -> Optional[Any]:
        """Fetch and deserialize JSON cached value."""
        redis = await get_redis_client()
        try:
            raw = await redis.get(f"{cls.PREFIX}{key}")
            if raw:
                return json.loads(raw)
            return None
        except Exception as e:
            logger.error(f"Cache get error for {key}: {e}")
            return None

    @classmethod
    async def set(cls, key: str, value: Any, ttl_seconds: int = 300) -> bool:
        """Serialize and store value in cache with TTL."""
        redis = await get_redis_client()
        try:
            serialized = json.dumps(value)
            await redis.set(f"{cls.PREFIX}{key}", serialized, ex=ttl_seconds)
            return True
        except Exception as e:
            logger.error(f"Cache set error for {key}: {e}")
            return False

    @classmethod
    async def delete(cls, key: str) -> bool:
        """Invalidate a specific cache key."""
        redis = await get_redis_client()
        try:
            await redis.delete(f"{cls.PREFIX}{key}")
            return True
        except Exception as e:
            logger.error(f"Cache delete error for {key}: {e}")
            return False

    @classmethod
    async def invalidate_user(cls, user_id: str) -> bool:
        """Invalidate all cached entities associated with a user."""
        redis = await get_redis_client()
        try:
            await redis.delete(
                f"{cls.PREFIX}user:{user_id}",
                f"{cls.PREFIX}user_perms:{user_id}",
                f"{cls.PREFIX}user_roles:{user_id}",
            )
            return True
        except Exception as e:
            logger.error(f"Failed to invalidate user cache {user_id}: {e}")
            return False


cache_service = CacheService()

