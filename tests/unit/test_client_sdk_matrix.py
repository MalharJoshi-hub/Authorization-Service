"""Comprehensive test matrix for Python Client SDK and FastAPI integration."""

import pytest
from unittest.mock import AsyncMock, patch
from auth_service.client.client import AaaSClient
from auth_service.client.fastapi_middleware import AaaSMiddlewareHandler
from fastapi import HTTPException


def test_aaas_client_init_and_headers():
    client = AaaSClient(
        base_url="https://auth.company.internal",
        api_key="aas_live_secret12345",
        tenant_id="tenant-prod-1",
    )
    assert client.base_url == "https://auth.company.internal"
    assert client.api_key == "aas_live_secret12345"

    headers_with_token = client._get_headers(token="custom-jwt-token")
    assert headers_with_token["Authorization"] == "Bearer custom-jwt-token"
    assert headers_with_token["X-Tenant-ID"] == "tenant-prod-1"

    headers_with_api_key = client._get_headers()
    assert headers_with_api_key["X-API-Key"] == "aas_live_secret12345"


@pytest.mark.asyncio
async def test_aaas_client_login_mock():
    client = AaaSClient()
    mock_resp = {
        "access_token": "access-123",
        "refresh_token": "refresh-123",
        "token_type": "bearer",
        "expires_in": 1800,
    }

    with patch.object(client, "login", new_callable=AsyncMock) as mock_login:
        mock_login.return_value = mock_resp
        res = await client.login("alex@test.org", "Pass123!")
        assert res["access_token"] == "access-123"
        assert res["expires_in"] == 1800


@pytest.mark.asyncio
async def test_aaas_middleware_handler_valid():
    client = AaaSClient()
    handler = AaaSMiddlewareHandler(client)

    mock_credentials = type("Creds", (), {"credentials": "valid-token"})()

    with patch.object(client, "introspect_token", new_callable=AsyncMock) as mock_introspect:
        mock_introspect.return_value = {
            "active": True,
            "sub": "user-42",
            "roles": ["developer", "member"],
            "permissions": ["read:code"],
        }

        claims = await handler.get_current_user_claims(credentials=mock_credentials)
        assert claims["active"] is True
        assert claims["sub"] == "user-42"


@pytest.mark.asyncio
async def test_aaas_middleware_handler_missing_credentials():
    client = AaaSClient()
    handler = AaaSMiddlewareHandler(client)

    with pytest.raises(HTTPException) as exc_info:
        await handler.get_current_user_claims(credentials=None)
    assert exc_info.value.status_code == 401


@pytest.mark.asyncio
async def test_aaas_middleware_handler_inactive_token():
    client = AaaSClient()
    handler = AaaSMiddlewareHandler(client)
    mock_credentials = type("Creds", (), {"credentials": "revoked-token"})()

    with patch.object(client, "introspect_token", new_callable=AsyncMock) as mock_introspect:
        mock_introspect.return_value = {"active": False}

        with pytest.raises(HTTPException) as exc_info:
            await handler.get_current_user_claims(credentials=mock_credentials)
        assert exc_info.value.status_code == 401
