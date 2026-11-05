"""Well-Known OpenID Discovery & JWKS Router (Layer 5: API).

Exposes RFC 7517 JSON Web Key Sets and RFC 8414 OpenID discovery metadata.
"""

from typing import Any, Dict
from fastapi import APIRouter, Request
from auth_service.core.security.jwt_validation import jwks_manager


router = APIRouter(prefix="/.well-known", tags=["OIDC Discovery & JWKS"])


@router.get(
    "/jwks.json",
    summary="Get JSON Web Key Set (JWKS)",
    description="Returns public keys for validating asymmetric token signatures.",
)
async def get_jwks() -> Dict[str, Any]:
    return jwks_manager.get_jwks()


@router.get(
    "/openid-configuration",
    summary="OpenID Connect Discovery Document",
    description="Returns discovery metadata describing endpoints, signing algorithms, and supported scopes.",
)
async def get_openid_configuration(request: Request) -> Dict[str, Any]:
    base_url = str(request.base_url).rstrip("/")
    return jwks_manager.get_openid_configuration(base_url)

