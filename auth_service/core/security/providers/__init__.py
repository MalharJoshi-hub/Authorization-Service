"""Social Identity & Enterprise Federation Providers (Layer 2).

Implements adapters for Google, GitHub, and Enterprise SAML 2.0 providers.
"""

from auth_service.core.security.providers.base import BaseOAuthProvider, OAuthUserProfile
from auth_service.core.security.providers.google import GoogleOAuthProvider
from auth_service.core.security.providers.github import GitHubOAuthProvider

__all__ = [
    "BaseOAuthProvider",
    "OAuthUserProfile",
    "GoogleOAuthProvider",
    "GitHubOAuthProvider",
]
