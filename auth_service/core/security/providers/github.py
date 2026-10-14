"""GitHub OAuth2 Identity Provider Adapter (Layer 2).

Encapsulates GitHub authorization, code-token exchanges, and profile hydration.
"""

from typing import Any, Dict, Optional
from urllib.parse import urlencode
import httpx
from auth_service.config import settings
from auth_service.core.exceptions import AuthenticationError
from auth_service.core.security.providers.base import BaseOAuthProvider, OAuthUserProfile, AuthorizationURL


class GitHubOAuthProvider(BaseOAuthProvider):
    """GitHub OAuth2 adapter."""

    AUTH_ENDPOINT = "https://github.com/login/oauth/authorize"
    TOKEN_ENDPOINT = "https://github.com/login/oauth/access_token"
    USERINFO_ENDPOINT = "https://api.github.com/user"
    EMAILS_ENDPOINT = "https://api.github.com/user/emails"

    def __init__(
        self,
        client_id: str = settings.GITHUB_CLIENT_ID,
        client_secret: str = settings.GITHUB_CLIENT_SECRET,
        redirect_uri: str = "",
    ):
        self.client_id = client_id
        self.client_secret = client_secret
        self.redirect_uri = redirect_uri

    @property
    def provider_name(self) -> str:
        return "github"

    def get_authorization_url(self, state: str = "", redirect_uri: Optional[str] = None) -> AuthorizationURL:
        redir = redirect_uri or self.redirect_uri or settings.GITHUB_REDIRECT_URI
        params = {
            "client_id": self.client_id,
            "redirect_uri": redir,
            "scope": "user:email read:user",
            "state": state,
        }
        url = f"{self.AUTH_ENDPOINT}?{urlencode(params)}"
        return AuthorizationURL(url, state)

    async def exchange_code_for_tokens(self, code: str, redirect_uri: Optional[str] = None) -> Dict[str, Any]:
        redir = redirect_uri or self.redirect_uri or settings.GITHUB_REDIRECT_URI
        if self.client_id.startswith("mock-"):
            return {
                "access_token": f"mock_github_token_{code}",
                "token_type": "bearer",
                "scope": "user:email",
            }

        headers = {"Accept": "application/json"}
        data = {
            "client_id": self.client_id,
            "client_secret": self.client_secret,
            "code": code,
            "redirect_uri": redir,
        }
        async with httpx.AsyncClient(timeout=10.0) as client:
            resp = await client.post(self.TOKEN_ENDPOINT, data=data, headers=headers)
            if resp.status_code != 200:
                raise AuthenticationError(f"GitHub token exchange failed: {resp.text}")
            return resp.json()

    async def fetch_user_profile(self, access_token: str) -> OAuthUserProfile:
        if access_token.startswith("mock_"):
            return OAuthUserProfile(
                provider="github",
                provider_user_id="github_mock_456",
                email="github.user@example.com",
                full_name="GitHub Mock User",
                avatar_url="https://avatars.githubusercontent.com/u/mock",
                raw_data={"mock": True},
            )

        headers = {
            "Authorization": f"Bearer {access_token}",
            "Accept": "application/json",
        }
        async with httpx.AsyncClient(timeout=10.0) as client:
            resp = await client.get(self.USERINFO_ENDPOINT, headers=headers)
            if resp.status_code != 200:
                raise AuthenticationError("Failed to fetch GitHub profile")
            raw = resp.json()

            email = raw.get("email")
            if not email:
                # Query emails endpoint
                email_resp = await client.get(self.EMAILS_ENDPOINT, headers=headers)
                if email_resp.status_code == 200:
                    for em in email_resp.json():
                        if em.get("primary") and em.get("verified"):
                            email = em.get("email")
                            break

            return OAuthUserProfile(
                provider="github",
                provider_user_id=str(raw.get("id")),
                email=email or "unlisted@github.user",
                full_name=raw.get("name") or raw.get("login"),
                avatar_url=raw.get("avatar_url"),
                raw_data=raw,
            )

    get_user_profile = fetch_user_profile

    async def exchange_code(self, code: str, redirect_uri: Optional[str] = None) -> Dict[str, Any]:
        """Alias for exchange_code_for_tokens."""
        return await self.exchange_code_for_tokens(code, redirect_uri)

    async def get_user_info(self, access_token: str) -> Dict[str, Any]:
        """Fetch and return raw/normalized profile dictionary."""
        profile = await self.fetch_user_profile(access_token)
        raw = profile.raw_data or {}
        return {
            "id": profile.provider_user_id,
            "login": raw.get("login", "octocat"),
            "email": profile.email,
            "name": profile.full_name,
            "picture": profile.avatar_url,
            "raw": raw,
        }


github_provider = GitHubOAuthProvider()
