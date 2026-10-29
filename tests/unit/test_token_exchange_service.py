"""Unit tests for RFC 8693 OAuth 2.0 Token Exchange."""

import pytest
from auth_service.core.exceptions import AuthorizationError
from auth_service.core.security.jwt_handler import encode_jwt
from auth_service.services.token_exchange_service import TokenExchangeService, TokenExchangeError


def test_token_exchange_success():
    service = TokenExchangeService()

    # Create valid subject token
    subject_claims = {
        "sub": "user-original",
        "permissions": ["read:data", "write:data", "admin:all"],
    }
    subject_token = encode_jwt(subject_claims)

    res = service.exchange_token(
        subject_token=subject_token,
        subject_token_type=service.TOKEN_TYPE_ACCESS_TOKEN,
        scope="read:data",
    )

    assert "access_token" in res
    assert res["token_type"] == "Bearer"
    assert res["scope"] == "read:data"


def test_token_exchange_with_actor_delegation():
    service = TokenExchangeService()

    subject_token = encode_jwt({"sub": "target-user", "permissions": ["read:data"]})
    actor_token = encode_jwt({"sub": "admin-actor", "permissions": ["impersonate"]})

    res = service.exchange_token(
        subject_token=subject_token,
        subject_token_type=service.TOKEN_TYPE_ACCESS_TOKEN,
        actor_token=actor_token,
        actor_token_type=service.TOKEN_TYPE_ACCESS_TOKEN,
    )

    assert "access_token" in res


def test_token_exchange_privilege_escalation_prevented():
    service = TokenExchangeService()

    subject_claims = {
        "sub": "normal-user",
        "permissions": ["read:data"],
    }
    subject_token = encode_jwt(subject_claims)

    # Attempting to request "admin:all" scope not in subject token must be rejected
    with pytest.raises(AuthorizationError):
        service.exchange_token(
            subject_token=subject_token,
            subject_token_type=service.TOKEN_TYPE_ACCESS_TOKEN,
            scope="read:data admin:all",
        )
