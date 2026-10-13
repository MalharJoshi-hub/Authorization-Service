"""Google OpenID Connect Identity Provider Adapter (Layer 2).

Encapsulates Google OAuth2 / OpenID Connect authorization and profile extraction.
"""

from typing import Any, Dict, Optional
from urllib.parse import urlencode
import httpx
from auth_service.config import settings
from auth_service.core.exceptions import AuthenticationError
from auth_service.core.security.providers.base import BaseOAuthProvider, OAuthUserProfile, AuthorizationURL


class GoogleOAuthProvider(BaseOAuthProvider):
    """Google OAuth2 and OpenID Connect adapter."""

    AUTH_ENDPOINT = "https://accounts.google.com/o/oauth2/v2/auth"
    TOKEN_ENDPOINT = "https://oauth2.googleapis.com/token"
    USERINFO_ENDPOINT = "https://www.googleapis.com/oauth2/v3/userinfo"

    def __init__(
        self,
        client_id: str = settings.GOOGLE_CLIENT_ID,
        client_secret: str = settings.GOOGLE_CLIENT_SECRET,
        redirect_uri: str = "",
    ):
        self.client_id = client_id
        self.client_secret = client_secret
        self.redirect_uri = redirect_uri

    @property
    def provider_name(self) -> str:
        return "google"

    def get_authorization_url(self, state: str = "", redirect_uri: Optional[str] = None) -> AuthorizationURL:
        redir = redirect_uri or self.redirect_uri or settings.GOOGLE_REDIRECT_URI
        params = {
            "client_id": self.client_id,
            "redirect_uri": redir,
            "response_type": "code",
            "scope": "openid email profile",
            "access_type": "offline",
            "state": state,
            "prompt": "select_account",
        }
        url = f"{self.AUTH_ENDPOINT}?{urlencode(params)}"
        return AuthorizationURL(url, state)

    async def exchange_code_for_tokens(self, code: str, redirect_uri: Optional[str] = None) -> Dict[str, Any]:
        redir = redirect_uri or self.redirect_uri or settings.GOOGLE_REDIRECT_URI
        if self.client_id.startswith("mock-"):
            return {
                "access_token": f"mock_google_token_{code}",
                "id_token": "mock_id_token",
                "token_type": "Bearer",
                "expires_in": 3600,
            }

        data = {
            "client_id": self.client_id,
            "client_secret": self.client_secret,
            "code": code,
            "grant_type": "authorization_code",
            "redirect_uri": redirect_uri,
        }
        async with httpx.AsyncClient(timeout=10.0) as client:
            resp = await client.post(self.TOKEN_ENDPOINT, data=data)
            if resp.status_code != 200:
                raise AuthenticationError(f"Google token exchange failed: {resp.text}")
            return resp.json()

    async def fetch_user_profile(self, access_token: str) -> OAuthUserProfile:
        if access_token.startswith("mock_"):
            return OAuthUserProfile(
                provider="google",
                provider_user_id="google_mock_123",
                email="google.user@example.com",
                full_name="Google Mock User",
                avatar_url="https://lh3.googleusercontent.com/mock.jpg",
                raw_data={"mock": True},
            )

        headers = {"Authorization": f"Bearer {access_token}"}
        async with httpx.AsyncClient(timeout=10.0) as client:
            resp = await client.get(self.USERINFO_ENDPOINT, headers=headers)
            if resp.status_code != 200:
                raise AuthenticationError("Failed to fetch Google profile")
            raw = resp.json()

            return OAuthUserProfile(
                provider="google",
                provider_user_id=raw.get("sub"),
                email=raw.get("email"),
                full_name=raw.get("name"),
                avatar_url=raw.get("picture"),
                raw_data=raw,
            )

    get_user_profile = fetch_user_profile

    async def exchange_code(self, code: str, redirect_uri: Optional[str] = None) -> Dict[str, Any]:
        """Alias for exchange_code_for_tokens."""
        return await self.exchange_code_for_tokens(code, redirect_uri)

    async def get_user_info(self, access_token: str) -> Dict[str, Any]:
        """Fetch and return raw/normalized profile dictionary."""
        profile = await self.fetch_user_profile(access_token)
        return {
            "id": profile.provider_user_id,
            "email": profile.email,
            "name": profile.full_name,
            "picture": profile.avatar_url,
            "raw": profile.raw_data,
        }


google_provider = GoogleOAuthProvider()
