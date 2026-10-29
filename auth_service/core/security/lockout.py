"""Brute Force Protection & Account Lockout Subsystem (Layer 1).

Monitors failed authentication attempts per account, applies automatic temporary
suspension when thresholds are exceeded, and supports administrative overrides.
"""

from typing import Tuple
from auth_service.config import settings
from auth_service.core.exceptions import AccountLockedError
from auth_service.core.logger import logger
from auth_service.storage.redis.client import get_redis_client


class AccountLockoutManager:
    """Manages consecutive failed authentication attempts and account lockouts."""

    ATTEMPTS_PREFIX = "lockout:attempts:"
    LOCKED_PREFIX = "lockout:locked:"

    @classmethod
    async def is_locked(cls, identifier: str) -> Tuple[bool, int]:
        """Check if an account identifier is currently locked out.

        Args:
            identifier: Normalized email address or user UUID.

        Returns:
            Tuple of (is_locked: bool, remaining_seconds: int).
        """
        redis = await get_redis_client()
        key = f"{cls.LOCKED_PREFIX}{identifier.lower().strip()}"
        try:
            ttl = await redis.ttl(key)
            if ttl > 0:
                return True, ttl
            return False, 0
        except Exception as e:
            logger.error(f"Error checking lockout status: {e}")
            return False, 0

    @classmethod
    async def record_failed_attempt(cls, identifier: str) -> Tuple[int, bool]:
        """Increment failed attempt counter and apply lockout if threshold reached.

        Args:
            identifier: Account identifier (email or user UUID).

        Returns:
            Tuple of (current_failed_count: int, is_now_locked: bool).
        """
        ident = identifier.lower().strip()
        attempts_key = f"{cls.ATTEMPTS_PREFIX}{ident}"
        locked_key = f"{cls.LOCKED_PREFIX}{ident}"

        redis = await get_redis_client()
        try:
            count = await redis.incr(attempts_key)
            # Expire attempts tracking after 30 minutes of inactivity
            await redis.expire(attempts_key, 1800)

            if count >= settings.LOCKOUT_MAX_ATTEMPTS:
                lockout_seconds = settings.LOCKOUT_DURATION_MINUTES * 60
                await redis.set(locked_key, "locked", ex=lockout_seconds)
                # Reset attempt counter once locked
                await redis.delete(attempts_key)
                logger.warning(
                    f"Account {ident} locked out for {settings.LOCKOUT_DURATION_MINUTES}m "
                    f"after {count} consecutive failed attempts."
                )
                return count, True

            return count, False
        except Exception as e:
            logger.error(f"Failed to record authentication failure: {e}")
            return 1, False

    @classmethod
    async def reset_attempts(cls, identifier: str) -> None:
        """Clear failed attempts counter upon successful authentication."""
        ident = identifier.lower().strip()
        redis = await get_redis_client()
        try:
            await redis.delete(f"{cls.ATTEMPTS_PREFIX}{ident}")
        except Exception as e:
            logger.error(f"Failed to clear login attempts: {e}")

    @classmethod
    async def unlock_account(cls, identifier: str) -> bool:
        """Manually unlock an account (used by admins or password reset)."""
        ident = identifier.lower().strip()
        redis = await get_redis_client()
        try:
            await redis.delete(f"{cls.LOCKED_PREFIX}{ident}", f"{cls.ATTEMPTS_PREFIX}{ident}")
            logger.info(f"Account {ident} manually unlocked.")
            return True
        except Exception as e:
            logger.error(f"Failed to manually unlock account: {e}")
            return False


lockout_manager = AccountLockoutManager()


class AccountLockoutTracker:
    """Synchronous memory-backed lockout tracker for unit testing and local caching."""

    def __init__(self, max_attempts: int = 5, lockout_minutes: int = 15):
        self.max_attempts = max_attempts
        self.lockout_minutes = lockout_minutes
        self._attempts = {}
        self._locked = {}

    def is_locked(self, identifier: str) -> bool:
        return self._locked.get(identifier, False)

    def record_failure(self, identifier: str) -> bool:
        count = self._attempts.get(identifier, 0) + 1
        self._attempts[identifier] = count
        if count >= self.max_attempts:
            self._locked[identifier] = True
            return True
        return False

    def reset(self, identifier: str) -> None:
        self._attempts.pop(identifier, None)
        self._locked.pop(identifier, None)

