"""Unit Tests for JWT Creation, Validation, and Claim Invariants (Phase 8: Layer 1)."""

from datetime import timedelta
import pytest
from auth_service.core.security.jwt_handler import (
    create_access_token,
    create_refresh_token,
    decode_token,
    get_token_jti,
)
from auth_service.core.exceptions import AuthenticationError


def test_create_and_decode_access_token():
    user_id = "user-12345"
    email = "test@example.com"
    tenant_id = "tenant-999"
    roles = ["admin", "member"]
    perms = ["users:read", "users:write"]

    token = create_access_token(
        user_id=user_id,
        email=email,
        tenant_id=tenant_id,
        roles=roles,
        permissions=perms,
    )

    claims = decode_token(token, expected_type="access")
    assert claims["sub"] == user_id
    assert claims["email"] == email
    assert claims["tenant_id"] == tenant_id
    assert claims["roles"] == roles
    assert claims["permissions"] == perms
    assert claims["token_type"] == "access"
    assert "jti" in claims
    assert "exp" in claims
    assert "iat" in claims


def test_create_and_decode_refresh_token():
    user_id = "user-54321"
    tenant_id = "tenant-888"

    refresh_meta = create_refresh_token(user_id=user_id, tenant_id=tenant_id)
    token = refresh_meta["token"]

    claims = decode_token(token, expected_type="refresh")
    assert claims["sub"] == user_id
    assert claims["tenant_id"] == tenant_id
    assert claims["token_type"] == "refresh"
    assert claims["family_id"] == refresh_meta["family_id"]
    assert claims["jti"] == refresh_meta["jti"]


def test_decode_token_type_mismatch():
    token = create_access_token(
        user_id="u1",
        email="u1@test.com",
        tenant_id="t1",
    )
    with pytest.raises(AuthenticationError) as exc_info:
        decode_token(token, expected_type="refresh")
    assert "Invalid token type" in str(exc_info.value)


def test_decode_expired_token():
    token = create_access_token(
        user_id="u1",
        email="u1@test.com",
        tenant_id="t1",
        expires_delta=timedelta(seconds=-10),  # expired 10 seconds ago
    )
    with pytest.raises(AuthenticationError) as exc_info:
        decode_token(token)
    assert exc_info.value.code == "TOKEN_EXPIRED"


def test_decode_tampered_token():
    token = create_access_token(
        user_id="u1",
        email="u1@test.com",
        tenant_id="t1",
    )
    # Alter the payload portion of the token
    parts = token.split(".")
    tampered = f"{parts[0]}.eyJob2d1cyI6ICJib2d1cyJ9.{parts[2]}"
    with pytest.raises(AuthenticationError) as exc_info:
        decode_token(tampered)
    assert exc_info.value.code == "TOKEN_INVALID"


def test_get_token_jti():
    token = create_access_token(
        user_id="u1",
        email="u1@test.com",
        tenant_id="t1",
    )
    claims = decode_token(token)
    extracted_jti = get_token_jti(token)
    assert extracted_jti == claims["jti"]
    assert get_token_jti("invalid-token") is None

