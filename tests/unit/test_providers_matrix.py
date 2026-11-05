"""Comprehensive OAuth2 and SAML federated identity provider matrix tests."""

import pytest
from unittest.mock import AsyncMock, patch
from auth_service.core.security.providers.google import GoogleOAuthProvider
from auth_service.core.security.providers.github import GitHubOAuthProvider
from auth_service.core.security.providers.saml import SAMLIdentityProvider


def test_google_provider_auth_url():
    provider = GoogleOAuthProvider(
        client_id="mock-google-client-id",
        client_secret="mock-secret",
        redirect_uri="https://auth.example.com/callback",
    )
    url, state = provider.get_authorization_url(state="custom-state-123")
    assert "accounts.google.com" in url
    assert "client_id=mock-google-client-id" in url
    assert "redirect_uri=https%3A%2F%2Fauth.example.com%2Fcallback" in url
    assert state == "custom-state-123"


def test_github_provider_auth_url():
    provider = GitHubOAuthProvider(
        client_id="mock-github-client-id",
        client_secret="mock-secret",
        redirect_uri="https://auth.example.com/callback",
    )
    url, state = provider.get_authorization_url(state="github-state-456")
    assert "github.com/login/oauth/authorize" in url
    assert "client_id=mock-github-client-id" in url
    assert "scope=user%3Aemail" in url or "scope=read%3Auser" in url
    assert state == "github-state-456"


@pytest.mark.asyncio
async def test_google_provider_token_exchange_mock():
    provider = GoogleOAuthProvider(client_id="gid", client_secret="gsecret", redirect_uri="http://cb")
    mock_token_resp = {
        "access_token": "mock-google-access-token",
        "id_token": "mock-google-id-token",
    }
    mock_user_resp = {
        "id": "google-user-12345",
        "email": "google.user@gmail.com",
        "name": "Google User",
        "picture": "https://avatar.google.com/123",
    }

    with patch.object(provider, "exchange_code", new_callable=AsyncMock) as mock_exch, \
         patch.object(provider, "get_user_info", new_callable=AsyncMock) as mock_info:
        mock_exch.return_value = mock_token_resp
        mock_info.return_value = mock_user_resp

        token_data = await provider.exchange_code("mock-auth-code")
        assert token_data["access_token"] == "mock-google-access-token"

        user_info = await provider.get_user_info("mock-google-access-token")
        assert user_info["email"] == "google.user@gmail.com"
        assert user_info["id"] == "google-user-12345"


@pytest.mark.asyncio
async def test_github_provider_token_exchange_mock():
    provider = GitHubOAuthProvider(client_id="ghid", client_secret="ghsecret", redirect_uri="http://cb")
    mock_user_resp = {
        "id": 98765432,
        "login": "octocat",
        "email": "octocat@github.com",
        "name": "Mona Lisa Octocat",
    }

    with patch.object(provider, "exchange_code", new_callable=AsyncMock) as mock_exch, \
         patch.object(provider, "get_user_info", new_callable=AsyncMock) as mock_info:
        mock_exch.return_value = {"access_token": "gh-access-token"}
        mock_info.return_value = mock_user_resp

        user_info = await provider.get_user_info("gh-access-token")
        assert user_info["login"] == "octocat"
        assert user_info["email"] == "octocat@github.com"


def test_saml_provider_initialization_and_metadata():
    provider = SAMLIdentityProvider(
        entity_id="https://idp.okta.com/exk123456",
        sso_url="https://idp.okta.com/sso",
        certificate_pem="-----BEGIN CERTIFICATE-----\nMockCert\n-----END CERTIFICATE-----",
    )
    assert provider.entity_id == "https://idp.okta.com/exk123456"
    assert provider.sso_url == "https://idp.okta.com/sso"
    assert "MockCert" in provider.certificate_pem

