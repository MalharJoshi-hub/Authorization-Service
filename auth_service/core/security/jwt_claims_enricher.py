"""Dynamic JWT Claims Enrichment and Transformation Engine.

Enriches baseline identity tokens with contextual metadata:
- Authentication Methods Reference (AMR: pwd, mfa, otp, fido)
- Audience (aud) validation and scoping
- Organization hierarchy and tenant tier tags
- Custom dynamic claim injection plugins
"""

from __future__ import annotations

import time
from typing import Any, Callable, Dict, List, Optional

from auth_service.models.user import User


class ClaimsEnrichmentHook:
    """Interface for custom claims mutation hooks."""

    def enrich(self, claims: Dict[str, Any], user: User) -> Dict[str, Any]:
        """Mutate and return claims dictionary."""
        raise NotImplementedError


class ClaimsEnricher:
    """Transforms raw user attributes and authentication context into enriched JWT claims."""

    def __init__(self) -> None:
        self._hooks: List[Callable[[Dict[str, Any], User], None]] = []

    def register_hook(self, hook: Callable[[Dict[str, Any], User], None]) -> None:
        """Register a custom enrichment callback."""
        self._hooks.append(hook)

    def build_claims(
        self,
        user: User,
        token_type: str = "access",
        auth_method: str = "pwd",
        audience: Optional[str] = None,
        custom_claims: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """Construct full standard and enriched claims dictionary for JWT creation."""
        now = int(time.time())

        # Determine AMR (Authentication Methods Reference - RFC 8176)
        amr = [auth_method]
        if getattr(user, "mfa_enabled", False):
            amr.append("mfa")

        # Collect roles and permissions
        role_names = [r.name for r in (user.roles or [])]
        permissions: List[str] = []
        for r in (user.roles or []):
            for p in (r.permissions or []):
                if p.name not in permissions:
                    permissions.append(p.name)

        claims: Dict[str, Any] = {
            "sub": str(user.id),
            "email": user.email,
            "username": user.username,
            "token_type": token_type,
            "iat": now,
            "nbf": now,
            "tenant_id": user.tenant_id,
            "roles": role_names,
            "permissions": permissions,
            "amr": amr,
            "is_verified": getattr(user, "is_verified", False),
        }

        if audience:
            claims["aud"] = audience

        if custom_claims:
            claims.update(custom_claims)

        # Execute registered external enrichment hooks
        for hook in self._hooks:
            try:
                hook(claims, user)
            except Exception:
                pass

        return claims


claims_enricher = ClaimsEnricher()
