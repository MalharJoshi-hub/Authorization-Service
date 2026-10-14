"""Abstract Base OAuth / OIDC Identity Provider (Layer 2).

Defines standard interface contracts for federated identity providers.
"""

from abc import ABC, abstractmethod
from typing import Any, Dict, NamedTuple, Optional


class AuthorizationURL(str):
    """String URL that also supports unpacking as (url, state)."""

    def __new__(cls, url: str, state: str = ""):
        obj = str.__new__(cls, url)
        obj.state = state
        return obj

    def __iter__(self):
        yield str(self)
        yield self.state


class OAuthUserProfile(NamedTuple):
    """Standardized user profile extracted from third-party identity providers."""

    provider: str
    provider_user_id: str
    email: str
    full_name: Optional[str] = None
    avatar_url: Optional[str] = None
    raw_data: Optional[Dict[str, Any]] = None


class BaseOAuthProvider(ABC):
    """Abstract contract for third-party OAuth2 and OIDC providers."""

    @property
    @abstractmethod
    def provider_name(self) -> str:
        """Normalized unique provider identifier (e.g. 'google', 'github')."""
        pass

    @abstractmethod
    def get_authorization_url(self, state: str, redirect_uri: str) -> str:
        """Construct external consent authorization redirect URL."""
        pass

    @abstractmethod
    async def exchange_code_for_tokens(self, code: str, redirect_uri: str) -> Dict[str, Any]:
        """Exchange authorization code for access and ID tokens."""
        pass

    @abstractmethod
    async def fetch_user_profile(self, access_token: str) -> OAuthUserProfile:
        """Fetch and normalize user profile from provider userinfo endpoint."""
        pass
