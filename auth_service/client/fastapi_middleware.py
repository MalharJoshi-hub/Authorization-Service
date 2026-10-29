"""Downstream FastAPI Integration Middleware (Client Library).

Provides turnkey FastAPI dependencies for external microservices to authenticate
inbound HTTP requests via AaaS Bearer tokens or API keys.
"""

from typing import Callable, List, Optional
from fastapi import Depends, Header, HTTPException, Request, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from auth_service.client.client import AaaSClient


security_bearer = HTTPBearer(auto_error=False)


class AaaSMiddlewareHandler:
    """Helper for downstream microservices to validate tokens against AaaS."""

    def __init__(self, aaas_client: AaaSClient):
        self.client = aaas_client

    async def get_current_user_claims(
        self,
        credentials: Optional[HTTPAuthorizationCredentials] = Depends(security_bearer),
    ) -> dict:
        """FastAPI route dependency resolving token claims via AaaS introspection."""
        if not credentials:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Missing Authorization Header",
                headers={"WWW-Authenticate": "Bearer"},
            )

        token = credentials.credentials
        introspection = await self.client.introspect_token(token)

        if not introspection.get("active"):
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Token invalid or revoked",
                headers={"WWW-Authenticate": "Bearer"},
            )

        return introspection

    def require_role(self, role_name: str) -> Callable:
        """Route guard enforcing required role."""
        async def dependency(claims: dict = Depends(self.get_current_user_claims)):
            roles = claims.get("roles", [])
            if role_name not in roles and "admin" not in roles and "superadmin" not in roles:
                raise HTTPException(
                    status_code=status.HTTP_403_FORBIDDEN,
                    detail=f"Role '{role_name}' required",
                )
            return claims

        return dependency

    def require_permission(self, permission_name: str) -> Callable:
        """Route guard enforcing required permission."""
        async def dependency(claims: dict = Depends(self.get_current_user_claims)):
            scope_str = claims.get("scope", "")
            scopes = set(scope_str.split())
            if permission_name not in scopes and "*" not in scopes and "admin:*" not in scopes:
                raise HTTPException(
                    status_code=status.HTTP_403_FORBIDDEN,
                    detail=f"Permission '{permission_name}' required",
                )
            return claims

        return dependency
