"""API Integration Tests for Well-Known OIDC Discovery and JWKS (Phase 8)."""

import pytest
from httpx import AsyncClient


@pytest.mark.asyncio
async def test_get_jwks(async_client: AsyncClient):
    response = await async_client.get("/.well-known/jwks.json")
    assert response.status_code == 200
    data = response.json()
    assert "keys" in data
    assert len(data["keys"]) >= 1
    key = data["keys"][0]
    assert key["kty"] == "RSA"
    assert key["use"] == "sig"
    assert key["alg"] == "RS256"


@pytest.mark.asyncio
async def test_get_openid_configuration(async_client: AsyncClient):
    response = await async_client.get("/.well-known/openid-configuration")
    assert response.status_code == 200
    data = response.json()
    assert "issuer" in data
    assert "authorization_endpoint" in data
    assert "token_endpoint" in data
    assert "jwks_uri" in data

