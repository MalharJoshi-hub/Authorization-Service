"""Unit tests for asynchronous Python client SDK."""

import pytest
from unittest.mock import AsyncMock, patch
from auth_service.client.python_client_async import AsyncAuthClient, AsyncAuthClientError


@pytest.mark.asyncio
async def test_async_client_context_manager():
    async with AsyncAuthClient(base_url="http://localhost:8000") as client:
        assert client.base_url == "http://localhost:8000"
        assert client._client is not None

    assert client._client is None


@pytest.mark.asyncio
async def test_async_client_headers():
    client = AsyncAuthClient(tenant_id="tenant-123", api_key="aaas_live_abc")
    client._access_token = "mock-jwt"

    headers = client._get_auth_headers()
    assert headers["Authorization"] == "Bearer mock-jwt"
    assert headers["X-Tenant-ID"] == "tenant-123"


@pytest.mark.asyncio
async def test_async_client_login():
    client = AsyncAuthClient()
    mock_resp = {"access_token": "token-xyz", "refresh_token": "ref-xyz", "expires_in": 3600}

    with patch.object(client, "_request", new_callable=AsyncMock) as mock_req:
        mock_req.return_value = mock_resp
        data = await client.login("testuser", "testpwd")

        assert data["access_token"] == "token-xyz"
        assert client._access_token == "token-xyz"
        assert client._refresh_token == "ref-xyz"


@pytest.mark.asyncio
async def test_async_client_refresh_missing_token():
    client = AsyncAuthClient()
    with pytest.raises(AsyncAuthClientError):
        await client.refresh()

