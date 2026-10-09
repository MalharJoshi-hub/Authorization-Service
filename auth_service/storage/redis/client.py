"""Async Redis Client & Connection Management with In-Memory Mock Fallback (Layer 4).

Allows running in production with live Redis, while seamlessly falling back to a
high-fidelity in-memory async store during tests or local setups without Redis.
"""

import time
import asyncio
from typing import Any, Dict, List, Optional, Set, Tuple
import redis.asyncio as aioredis
from auth_service.config import settings
from auth_service.core.logger import logger


class InMemoryRedis:
    """Async in-memory mock replicating essential Redis operations."""

    def __init__(self):
        self._data: Dict[str, Any] = {}
        self._expires: Dict[str, float] = {}
        self._sorted_sets: Dict[str, Dict[str, float]] = {}

    def _is_expired(self, key: str) -> bool:
        if key in self._expires:
            if time.time() > self._expires[key]:
                self._data.pop(key, None)
                self._expires.pop(key, None)
                self._sorted_sets.pop(key, None)
                return True
        return False

    async def get(self, key: str) -> Optional[str]:
        if self._is_expired(key):
            return None
        val = self._data.get(key)
        return str(val) if val is not None else None

    async def set(self, key: str, value: Any, ex: Optional[int] = None) -> bool:
        self._data[key] = str(value)
        if ex is not None:
            self._expires[key] = time.time() + ex
        else:
            self._expires.pop(key, None)
        return True

    async def delete(self, *keys: str) -> int:
        count = 0
        for k in keys:
            if k in self._data or k in self._sorted_sets:
                self._data.pop(k, None)
                self._expires.pop(k, None)
                self._sorted_sets.pop(k, None)
                count += 1
        return count

    async def exists(self, *keys: str) -> int:
        count = 0
        for k in keys:
            if not self._is_expired(k) and (k in self._data or k in self._sorted_sets):
                count += 1
        return count

    async def incr(self, key: str) -> int:
        self._is_expired(key)
        val = int(self._data.get(key, 0)) + 1
        self._data[key] = str(val)
        return val

    async def expire(self, key: str, seconds: int) -> bool:
        if key in self._data or key in self._sorted_sets:
            self._expires[key] = time.time() + seconds
            return True
        return False

    async def ttl(self, key: str) -> int:
        if key in self._expires:
            remaining = int(self._expires[key] - time.time())
            return remaining if remaining > 0 else -2
        if key in self._data or key in self._sorted_sets:
            return -1
        return -2

    async def zadd(self, name: str, mapping: Dict[str, float]) -> int:
        self._is_expired(name)
        if name not in self._sorted_sets:
            self._sorted_sets[name] = {}
        added = 0
        for member, score in mapping.items():
            if member not in self._sorted_sets[name]:
                added += 1
            self._sorted_sets[name][member] = float(score)
        return added

    async def zremrangebyscore(self, name: str, min_score: float, max_score: float) -> int:
        self._is_expired(name)
        if name not in self._sorted_sets:
            return 0
        to_del = [
            m for m, s in self._sorted_sets[name].items()
            if min_score <= s <= max_score
        ]
        for m in to_del:
            del self._sorted_sets[name][m]
        return len(to_del)

    async def zcard(self, name: str) -> int:
        self._is_expired(name)
        return len(self._sorted_sets.get(name, {}))

    async def flushdb(self) -> bool:
        self._data.clear()
        self._expires.clear()
        self._sorted_sets.clear()
        return True

    async def ping(self) -> bool:
        return True

    async def close(self) -> None:
        pass


_redis_instance: Optional[Any] = None
_in_memory_instance: Optional[InMemoryRedis] = None


async def get_redis_client() -> Any:
    """Retrieve active Redis client (live connection or in-memory fallback)."""
    global _redis_instance, _in_memory_instance

    if _redis_instance is not None:
        return _redis_instance

    if _in_memory_instance is not None:
        return _in_memory_instance

    # Attempt connection to configured live Redis instance
    try:
        client = aioredis.from_url(
            settings.REDIS_URL,
            encoding="utf-8",
            decode_responses=True,
            socket_timeout=settings.REDIS_TIMEOUT_SECONDS,
            socket_connect_timeout=settings.REDIS_TIMEOUT_SECONDS,
        )
        # Test connection ping with timeout
        await asyncio.wait_for(client.ping(), timeout=1.0)
        _redis_instance = client
        logger.info("Connected to live Redis cluster")
        return _redis_instance
    except Exception as e:
        logger.warning(f"Could not connect to Redis at {settings.REDIS_URL} ({e}). Using in-memory store.")
        _in_memory_instance = InMemoryRedis()
        return _in_memory_instance


async def close_redis_client() -> None:
    """Cleanly close Redis connections during application shutdown."""
    global _redis_instance, _in_memory_instance
    if _redis_instance is not None:
        try:
            await _redis_instance.close()
        except Exception:
            pass
        _redis_instance = None
    if _in_memory_instance is not None:
        await _in_memory_instance.close()
        _in_memory_instance = None
