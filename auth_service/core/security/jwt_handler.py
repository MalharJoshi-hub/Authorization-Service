"""JSON Web Token (JWT) Generation, Validation, and Claims Management (Layer 1).

Implements cryptographically signed JWTs conforming to RFC 7519 with standard
claims (sub, exp, iat, nbf, jti), tenant scopes, and role claims.
"""

import uuid
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List, Optional
import jwt
from auth_service.config import settings
from auth_service.core.exceptions import AuthenticationError


def create_access_token(
    user_id: str,
    email: str,
    tenant_id: str,
    roles: Optional[List[str]] = None,
    permissions: Optional[List[str]] = None,
    expires_delta: Optional[timedelta] = None,
    extra_claims: Optional[Dict[str, Any]] = None,
) -> str:
    """Generate a signed JWT access token.

    Args:
        user_id: The primary subject identifier.
        email: User email address.
        tenant_id: The tenant/organization boundary.
        roles: List of assigned role names.
        permissions: List of resolved permission strings.
        expires_delta: Optional custom lifetime duration.
        extra_claims: Optional supplementary payload claims.

    Returns:
        The encoded compact JWT string.
    """
    now = datetime.now(timezone.utc)
    expire = now + (expires_delta or timedelta(minutes=settings.ACCESS_TOKEN_EXPIRE_MINUTES))
    jti = str(uuid.uuid4())

    payload: Dict[str, Any] = {
        "sub": str(user_id),
        "email": email,
        "tenant_id": str(tenant_id),
        "roles": roles or [],
        "permissions": permissions or [],
        "token_type": "access",
        "jti": jti,
        "iat": int(now.timestamp()),
        "nbf": int(now.timestamp()),
        "exp": int(expire.timestamp()),
    }

    if extra_claims:
        for k, v in extra_claims.items():
            if k not in payload:
                payload[k] = v

    encoded = jwt.encode(payload, settings.JWT_SECRET_KEY, algorithm=settings.JWT_ALGORITHM)
    return encoded


def create_refresh_token(
    user_id: str,
    tenant_id: str,
    family_id: Optional[str] = None,
    expires_delta: Optional[timedelta] = None,
) -> Dict[str, Any]:
    """Generate a signed JWT refresh token for session lifecycle maintenance.

    Args:
        user_id: Subject user identifier.
        tenant_id: Tenant context identifier.
        family_id: Unique token family group identifier for rotation tracking.
        expires_delta: Optional expiration override.

    Returns:
        Dictionary containing raw token, jti, family_id, and exp timestamp.
    """
    now = datetime.now(timezone.utc)
    expire = now + (expires_delta or timedelta(days=settings.REFRESH_TOKEN_EXPIRE_DAYS))
    jti = str(uuid.uuid4())
    fam_id = family_id or str(uuid.uuid4())

    payload: Dict[str, Any] = {
        "sub": str(user_id),
        "tenant_id": str(tenant_id),
        "token_type": "refresh",
        "family_id": fam_id,
        "jti": jti,
        "iat": int(now.timestamp()),
        "exp": int(expire.timestamp()),
    }

    token = jwt.encode(payload, settings.JWT_SECRET_KEY, algorithm=settings.JWT_ALGORITHM)
    return {
        "token": token,
        "jti": jti,
        "family_id": fam_id,
        "expires_at": expire,
    }


def decode_token(token: str, expected_type: Optional[str] = None) -> Dict[str, Any]:
    """Decode and cryptographically verify a JWT.

    Args:
        token: Raw encoded JWT string.
        expected_type: Optional required token_type claim ('access' or 'refresh').

    Returns:
        Decoded claims dictionary.

    Raises:
        AuthenticationError: If signature is invalid, token is expired, or claims are malformed.
    """
    try:
        payload = jwt.decode(
            token,
            settings.JWT_SECRET_KEY,
            algorithms=[settings.JWT_ALGORITHM],
            options={"require": ["exp", "sub", "jti"]},
        )

        if expected_type and payload.get("token_type") != expected_type:
            raise AuthenticationError(
                f"Invalid token type. Expected '{expected_type}', got '{payload.get('token_type')}'"
            )

        return payload

    except jwt.ExpiredSignatureError:
        raise AuthenticationError("Token has expired", code="TOKEN_EXPIRED")
    except jwt.InvalidTokenError as e:
        raise AuthenticationError(f"Invalid token signature or payload: {str(e)}", code="TOKEN_INVALID")


def get_token_jti(token: str) -> Optional[str]:
    """Extract JTI claim from token without verifying signature (useful for revoking expired tokens)."""
    try:
        unverified = jwt.decode(token, options={"verify_signature": False})
        return unverified.get("jti")
    except Exception:
        return None


def encode_jwt(claims: Dict[str, Any], secret_key: Optional[str] = None, algorithm: Optional[str] = None) -> str:
    """Encode arbitrary claims into a signed JWT."""
    key = secret_key or settings.JWT_SECRET_KEY
    algo = algorithm or settings.JWT_ALGORITHM
    c = dict(claims)
    if "exp" not in c:
        c["exp"] = int(datetime.now(timezone.utc).timestamp()) + 3600
    if "iat" not in c:
        c["iat"] = int(datetime.now(timezone.utc).timestamp())
    return jwt.encode(c, key, algorithm=algo)


def decode_jwt(
    token: str,
    secret_key: Optional[str] = None,
    algorithm: Optional[str] = None,
    audience: Optional[str] = None,
    options: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    """Decode and extract payload from a JWT."""
    key = secret_key or settings.JWT_SECRET_KEY
    algo = algorithm or settings.JWT_ALGORITHM
    opts = {"verify_exp": False, "verify_aud": False}
    if options:
        opts.update(options)
    return jwt.decode(token, key, algorithms=[algo], audience=audience, options=opts)

