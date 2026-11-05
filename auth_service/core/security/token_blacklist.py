"""Token Blacklist Subsystem (Layer 1).

Maintains a distributed blacklist of revoked JWT Unique Identifiers (JTI)
stored in Redis with automatic TTL expiration matching token lifetimes.
"""

from typing import Optional
from auth_service.core.logger import logger
from auth_service.storage.redis.client import get_redis_client


class TokenBlacklist:
    """Manages instant token revocation via Redis or in-memory fallback."""

    PREFIX = "token:blacklist:"

    @classmethod
    async def blacklist_token(cls, jti: str, ttl_seconds: int) -> bool:
        """Add a token JTI to the blacklist with a defined TTL.

        Args:
            jti: Unique identifier of the token.
            ttl_seconds: Remaining validity duration of the token in seconds.

        Returns:
            True if successfully blacklisted, False otherwise.
        """
        if not jti:
            return False

        # If token has already expired, no need to blacklist
        if ttl_seconds <= 0:
            return True

        key = f"{cls.PREFIX}{jti}"
        redis = await get_redis_client()
        try:
            await redis.set(key, "revoked", ex=max(int(ttl_seconds), 1))
            logger.info(f"Token {jti} blacklisted for {ttl_seconds}s")
            return True
        except Exception as e:
            logger.error(f"Failed to blacklist token {jti}: {e}")
            return False

    @classmethod
    async def is_blacklisted(cls, jti: Optional[str]) -> bool:
        """Check if a token JTI has been revoked.

        Args:
            jti: Token unique identifier.

        Returns:
            True if the token is present in the blacklist, False otherwise.
        """
        if not jti:
            return False

        key = f"{cls.PREFIX}{jti}"
        redis = await get_redis_client()
        try:
            val = await redis.get(key)
            return val is not None
        except Exception as e:
            logger.error(f"Error checking blacklist for token {jti}: {e}")
            return False


token_blacklist = TokenBlacklist()

