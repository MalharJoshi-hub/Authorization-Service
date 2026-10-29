"""OpenID Connect (OIDC) Discovery & JWKS Management (Layer 1).

Generates RFC 7517 JSON Web Key Sets (JWKS) and RFC 8414 OpenID Connect
Discovery Configuration for external client federation.
"""

import base64
import json
from typing import Any, Dict, List
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
from auth_service.config import settings


def int_to_base64url(val: int) -> str:
    """Convert an integer to a URL-safe Base64 encoded string."""
    byte_length = (val.bit_length() + 7) // 8
    val_bytes = val.to_bytes(byte_length, "big")
    return base64.urlsafe_b64encode(val_bytes).decode("utf-8").rstrip("=")


class JWKSManager:
    """Manages asymmetric signing keys and public JWKS document."""

    def __init__(self):
        # Generate baseline RSA 2048-bit keypair for demonstrations and token verification
        self._private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
        )
        self._public_key = self._private_key.public_key()
        self.kid = "aas-rsa-key-2026-v1"

    def get_jwks(self) -> Dict[str, Any]:
        """Construct public RFC 7517 JSON Web Key Set."""
        public_numbers = self._public_key.public_numbers()
        e_b64 = int_to_base64url(public_numbers.e)
        n_b64 = int_to_base64url(public_numbers.n)

        jwk = {
            "kty": "RSA",
            "use": "sig",
            "alg": "RS256",
            "kid": self.kid,
            "n": n_b64,
            "e": e_b64,
        }
        return {"keys": [jwk]}

    def set_cached_jwks(self, jwks: Dict[str, Any]) -> None:
        """Store externally fetched or rotated JWKS document."""
        self._cached_jwks = jwks

    def get_key_by_kid(self, kid: str) -> Optional[Dict[str, Any]]:
        """Find key in JWKS document by key ID."""
        doc = getattr(self, "_cached_jwks", None) or self.get_jwks()
        for key in doc.get("keys", []):
            if key.get("kid") == kid:
                return key
        return None

    def get_openid_configuration(self, base_url: str = "http://localhost:8000") -> Dict[str, Any]:
        """Generate OpenID Connect Provider Configuration."""
        prefix = f"{base_url}{settings.API_PREFIX}"
        return {
            "issuer": base_url,
            "authorization_endpoint": f"{prefix}/oauth/google",
            "token_endpoint": f"{prefix}/auth/login",
            "userinfo_endpoint": f"{prefix}/users/me",
            "jwks_uri": f"{base_url}/.well-known/jwks.json",
            "registration_endpoint": f"{prefix}/auth/register",
            "scopes_supported": ["openid", "profile", "email", "offline_access"],
            "response_types_supported": ["code", "token", "id_token"],
            "subject_types_supported": ["public"],
            "id_token_signing_alg_values_supported": ["RS256", "HS256"],
            "token_endpoint_auth_methods_supported": [
                "client_secret_basic",
                "client_secret_post",
            ],
            "claims_supported": [
                "sub",
                "iss",
                "aud",
                "exp",
                "iat",
                "email",
                "full_name",
                "tenant_id",
                "roles",
            ],
        }


jwks_manager = JWKSManager()
