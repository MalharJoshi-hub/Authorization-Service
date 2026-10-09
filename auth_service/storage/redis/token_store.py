"""Redis Transient Token Store (Layer 4).

Manages high-entropy temporary tokens for email verification workflows and
password reset authorizations with automatic time-to-live eviction.
"""

import json
import secrets
from typing import Any, Dict, Optional
from auth_service.config import settings
from auth_service.core.logger import logger
from auth_service.storage.redis.client import get_redis_client


class RedisTokenStore:
    """Stores one-time verification and password reset authorization tokens."""

    EMAIL_VERIFY_PREFIX = "token:email_verify:"
    PASSWORD_RESET_PREFIX = "token:password_reset:"

    @classmethod
    async def create_email_verification_token(
        cls,
        user_id: str,
        email: str,
        tenant_id: str,
        ttl_hours: Optional[int] = None,
    ) -> str:
        """Issue high-entropy URL-safe token for account email verification."""
        token = secrets.token_urlsafe(32)
        ttl = (ttl_hours or settings.EMAIL_VERIFICATION_TTL_HOURS) * 3600
        key = f"{cls.EMAIL_VERIFY_PREFIX}{token}"

        data = {
            "user_id": user_id,
            "email": email.lower().strip(),
            "tenant_id": tenant_id,
        }

        redis = await get_redis_client()
        await redis.set(key, json.dumps(data), ex=ttl)
        logger.info(f"Created email verification token for user {user_id}")
        return token

    @classmethod
    async def verify_and_consume_email_token(cls, token: str) -> Optional[Dict[str, Any]]:
        """Verify and atomically consume email verification token."""
        if not token:
            return None

        key = f"{cls.EMAIL_VERIFY_PREFIX}{token.strip()}"
        redis = await get_redis_client()
        raw = await redis.get(key)
        if not raw:
            return None

        # Atomically delete upon consumption
        await redis.delete(key)
        try:
            return json.loads(raw)
        except Exception:
            return None

    @classmethod
    async def create_password_reset_token(
        cls,
        user_id: str,
        email: str,
        tenant_id: str,
        ttl_hours: Optional[int] = None,
    ) -> str:
        """Issue high-entropy token for password recovery."""
        token = secrets.token_urlsafe(32)
        ttl = (ttl_hours or settings.PASSWORD_RESET_TTL_HOURS) * 3600
        key = f"{cls.PASSWORD_RESET_PREFIX}{token}"

        data = {
            "user_id": user_id,
            "email": email.lower().strip(),
            "tenant_id": tenant_id,
        }

        redis = await get_redis_client()
        await redis.set(key, json.dumps(data), ex=ttl)
        logger.info(f"Created password reset token for user {user_id}")
        return token

    @classmethod
    async def verify_password_reset_token(cls, token: str) -> Optional[Dict[str, Any]]:
        """Verify validity of password reset token without consuming it."""
        if not token:
            return None

        key = f"{cls.PASSWORD_RESET_PREFIX}{token.strip()}"
        redis = await get_redis_client()
        raw = await redis.get(key)
        if not raw:
            return None

        try:
            return json.loads(raw)
        except Exception:
            return None

    @classmethod
    async def consume_password_reset_token(cls, token: str) -> Optional[Dict[str, Any]]:
        """Consume and invalidate password reset token upon successful password update."""
        if not token:
            return None

        key = f"{cls.PASSWORD_RESET_PREFIX}{token.strip()}"
        redis = await get_redis_client()
        raw = await redis.get(key)
        if not raw:
            return None

        await redis.delete(key)
        try:
            return json.loads(raw)
        except Exception:
            return None


redis_token_store = RedisTokenStore()
