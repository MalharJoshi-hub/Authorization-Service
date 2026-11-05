"""RFC 7662 Token Introspection & RFC 7009 Revocation Service (Layer 1 & Layer 2).

Standardizes machine-to-machine validation of active tokens for resource servers
and downstream microservices.
"""

from datetime import datetime, timezone
from typing import Any, Dict, Optional
from sqlalchemy.ext.asyncio import AsyncSession
from auth_service.core.security.jwt_handler import decode_token, get_token_jti
from auth_service.core.security.token_blacklist import token_blacklist
from auth_service.core.security.token_rotation import hash_token
from auth_service.storage.postgres.token_repo import TokenRepository
from auth_service.storage.postgres.user_repo import UserRepository


class TokenIntrospectionService:
    """Evaluates token active status according to RFC 7662."""

    async def introspect(
        self,
        db: AsyncSession,
        token: str,
        token_type_hint: Optional[str] = None,
    ) -> Dict[str, Any]:
        """Introspect an access or refresh token and return standard claims envelope."""
        if not token:
            return {"active": False}

        try:
            # 1. Decode token claims
            claims = decode_token(token)
            jti = claims.get("jti")
            user_id = claims.get("sub")
            tenant_id = claims.get("tenant_id")
            token_type = claims.get("token_type")

            # 2. Check Redis blacklist for access tokens
            if token_type == "access" and jti:
                if await token_blacklist.is_blacklisted(jti):
                    return {"active": False}

            # 3. Check DB revocation for refresh tokens
            if token_type == "refresh":
                token_repo = TokenRepository(db)
                digest = hash_token(token)
                stored = await token_repo.get_by_hash(digest)
                if not stored or stored.is_revoked:
                    return {"active": False}

            # 4. Check user account active status
            user_repo = UserRepository(db)
            user = await user_repo.get_by_id(user_id, tenant_id=tenant_id)
            if not user or not user.is_active:
                return {"active": False}

            # Token is fully valid and active
            return {
                "active": True,
                "scope": " ".join(claims.get("permissions", [])),
                "sub": user.id,
                "email": user.email,
                "tenant_id": user.tenant_id,
                "roles": claims.get("roles", []),
                "token_type": token_type,
                "exp": claims.get("exp"),
                "iat": claims.get("iat"),
                "jti": jti,
            }

        except Exception:
            return {"active": False}

    async def revoke(
        self,
        db: AsyncSession,
        token: str,
        token_type_hint: Optional[str] = None,
    ) -> bool:
        """Revoke token according to RFC 7009."""
        if not token:
            return True

        jti = get_token_jti(token)
        if jti:
            # Blacklist for 24 hours
            await token_blacklist.blacklist_token(jti, 86400)

        # Also check if it's a refresh token and revoke in DB
        try:
            token_repo = TokenRepository(db)
            digest = hash_token(token)
            stored = await token_repo.get_by_hash(digest)
            if stored:
                await token_repo.revoke_token(stored.id)
        except Exception:
            pass

        return True


token_introspection_service = TokenIntrospectionService()

