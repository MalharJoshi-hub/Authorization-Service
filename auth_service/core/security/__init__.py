"""Security Core Subsystem (Layer 1).

Encapsulates password hashing, JWT creation & verification, cryptographic
token rotation, API key management, rate limiting, and brute force defenses.
"""

from auth_service.core.security.password import (
    hash_password,
    verify_password,
    validate_password_complexity,
)
from auth_service.core.security.jwt_handler import (
    create_access_token,
    create_refresh_token,
    decode_token,
    get_token_jti,
)
from auth_service.core.security.api_keys import (
    generate_api_key,
    hash_api_key,
    verify_api_key,
)
from auth_service.core.security.rate_limiter import RateLimiter

__all__ = [
    "hash_password",
    "verify_password",
    "validate_password_complexity",
    "create_access_token",
    "create_refresh_token",
    "decode_token",
    "get_token_jti",
    "generate_api_key",
    "hash_api_key",
    "verify_api_key",
    "RateLimiter",
]

