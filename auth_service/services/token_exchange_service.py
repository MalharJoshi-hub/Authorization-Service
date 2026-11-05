"""RFC 8693 OAuth 2.0 Token Exchange Service.

Implements token exchange specification primitives:
- Subject token verification and down-scoping
- Actor token delegation (act claim)
- Impersonation semantics and audit tracking
- Security policies preventing privilege escalation
"""

from __future__ import annotations

import time
from typing import Any, Dict, List, Optional, Tuple

from auth_service.core.exceptions import AuthenticationError, AuthorizationError
from auth_service.core.logger import get_logger
from auth_service.core.security.jwt_handler import decode_jwt, encode_jwt

logger = get_logger("auth_service.services.token_exchange")


class TokenExchangeError(AuthenticationError):
    """Raised when token exchange fails validation."""

    def __init__(self, message: str, error: str = "invalid_request") -> None:
        super().__init__(message=message, code=f"TOKEN_EXCHANGE_{error.upper()}")
        self.oauth_error = error


class TokenExchangeService:
    """Manages RFC 8693 token exchange flows."""

    TOKEN_TYPE_ACCESS_TOKEN = "urn:ietf:params:oauth:token-type:access_token"
    TOKEN_TYPE_REFRESH_TOKEN = "urn:ietf:params:oauth:token-type:refresh_token"
    TOKEN_TYPE_ID_TOKEN = "urn:ietf:params:oauth:token-type:id_token"

    def __init__(self) -> None:
        pass

    def validate_requested_token_type(self, token_type: Optional[str]) -> str:
        """Validate and return requested target token type."""
        target = token_type or self.TOKEN_TYPE_ACCESS_TOKEN
        valid_types = {
            self.TOKEN_TYPE_ACCESS_TOKEN,
            self.TOKEN_TYPE_REFRESH_TOKEN,
            self.TOKEN_TYPE_ID_TOKEN,
        }
        if target not in valid_types:
            raise TokenExchangeError(f"Unsupported requested_token_type: {target}", "unsupported_token_type")
        return target

    def exchange_token(
        self,
        subject_token: str,
        subject_token_type: str,
        actor_token: Optional[str] = None,
        actor_token_type: Optional[str] = None,
        requested_token_type: Optional[str] = None,
        scope: Optional[str] = None,
        audience: Optional[str] = None,
    ) -> Dict[str, Any]:
        """Perform token exchange ceremony."""
        # 1. Decode subject token
        try:
            subject_claims = decode_jwt(subject_token)
        except Exception as exc:
            raise TokenExchangeError(f"Invalid subject token: {exc}", "invalid_grant") from exc

        # 2. Check actor token if delegation requested
        act_claim: Optional[Dict[str, Any]] = None
        if actor_token:
            try:
                actor_claims = decode_jwt(actor_token)
                act_claim = {
                    "sub": actor_claims.get("sub"),
                    "iss": actor_claims.get("iss", "auth-service"),
                }
            except Exception as exc:
                raise TokenExchangeError(f"Invalid actor token: {exc}", "invalid_grant") from exc

        # 3. Determine scopes (down-scoping only)
        original_scopes = subject_claims.get("permissions", [])
        requested_scopes = scope.split() if scope else []

        if requested_scopes:
            # Cannot request scopes not in original token
            for s in requested_scopes:
                if s not in original_scopes:
                    raise AuthorizationError(f"Cannot escalate privileges; scope '{s}' not in subject token")
            final_scopes = requested_scopes
        else:
            final_scopes = original_scopes

        # 4. Mint exchanged token
        new_claims = dict(subject_claims)
        new_claims["permissions"] = final_scopes
        new_claims["iat"] = int(time.time())
        new_claims["token_type"] = "access"

        if audience:
            new_claims["aud"] = audience

        if act_claim:
            new_claims["act"] = act_claim

        exchanged_token = encode_jwt(new_claims)

        logger.info(
            "RFC 8693 token exchange successful for sub=%s (delegated=%s)",
            subject_claims.get("sub"),
            bool(act_claim),
        )

        return {
            "access_token": exchanged_token,
            "issued_token_type": self.TOKEN_TYPE_ACCESS_TOKEN,
            "token_type": "Bearer",
            "expires_in": 900,
            "scope": " ".join(final_scopes),
        }


token_exchange_service = TokenExchangeService()

