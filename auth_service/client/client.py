"""Async Client SDK for Auth-as-a-Service (Client Library).

Provides high-throughput async HTTP client methods for external services integrating
with the AaaS authentication and authorization platform.
"""

from typing import Any, Dict, List, Optional
import httpx
from auth_service.core.exceptions import AuthenticationError, AuthorizationError, AaaSException


class AaaSClient:
    """Enterprise client SDK for communicating with an AaaS server instance."""

    def __init__(
        self,
        base_url: str = "http://localhost:8000",
        api_prefix: str = "/api/v1",
        api_key: Optional[str] = None,
        tenant_id: Optional[str] = None,
        timeout: float = 10.0,
    ):
        self.base_url = base_url.rstrip("/")
        self.api_prefix = api_prefix.rstrip("/")
        self.api_key = api_key
        self.tenant_id = tenant_id
        self.timeout = timeout
        self._http_client: Optional[httpx.AsyncClient] = None

    def _get_headers(self, token: Optional[str] = None) -> Dict[str, str]:
        headers: Dict[str, str] = {
            "Accept": "application/json",
            "Content-Type": "application/json",
            "User-Agent": "AaaS-Python-SDK/1.0.0",
        }
        if token:
            headers["Authorization"] = f"Bearer {token}"
        elif self.api_key:
            headers["X-API-Key"] = self.api_key

        if self.tenant_id:
            headers["X-Tenant-ID"] = self.tenant_id

        return headers

    async def get_client(self) -> httpx.AsyncClient:
        """Provide or construct underlying httpx AsyncClient instance."""
        if self._http_client is None or self._http_client.is_closed:
            self._http_client = httpx.AsyncClient(
                base_url=self.base_url,
                timeout=self.timeout,
            )
        return self._http_client

    async def close(self) -> None:
        """Dispose of active HTTP connection pools."""
        if self._http_client and not self._http_client.is_closed:
            await self._http_client.aclose()
            self._http_client = None

    async def __aenter__(self):
        await self.get_client()
        return self

    async def __aexit__(self, exc_type, exc_val, exc_tb):
        await self.close()

    async def login(self, email: str, password: str, tenant_id: Optional[str] = None) -> Dict[str, Any]:
        """Authenticate user credentials and receive access/refresh tokens."""
        client = await self.get_client()
        payload = {
            "email": email,
            "password": password,
            "tenant_id": tenant_id or self.tenant_id,
        }
        resp = await client.post(
            f"{self.api_prefix}/auth/login",
            json=payload,
            headers=self._get_headers(),
        )
        if resp.status_code != 200:
            raise AuthenticationError(f"Login failed: {resp.text}")
        return resp.json()

    async def refresh_token(self, refresh_token: str) -> Dict[str, Any]:
        """Rotate a refresh token for a fresh token pair."""
        client = await self.get_client()
        resp = await client.post(
            f"{self.api_prefix}/auth/refresh",
            json={"refresh_token": refresh_token},
            headers=self._get_headers(),
        )
        if resp.status_code != 200:
            raise AuthenticationError(f"Token refresh failed: {resp.text}")
        return resp.json()

    async def logout(self, access_token: str, refresh_token: Optional[str] = None) -> bool:
        """Revoke active access and refresh token sessions."""
        client = await self.get_client()
        payload = {"refresh_token": refresh_token} if refresh_token else {}
        resp = await client.post(
            f"{self.api_prefix}/auth/logout",
            json=payload,
            headers=self._get_headers(token=access_token),
        )
        return resp.status_code == 200

    async def introspect_token(self, token: str) -> Dict[str, Any]:
        """Validate token active status and retrieve metadata via RFC 7662."""
        client = await self.get_client()
        resp = await client.post(
            f"{self.api_prefix}/oauth/introspect",
            json={"token": token},
            headers=self._get_headers(),
        )
        if resp.status_code != 200:
            return {"active": False}
        return resp.json()

    async def get_current_user(self, access_token: str) -> Dict[str, Any]:
        """Fetch profile for authenticated token."""
        client = await self.get_client()
        resp = await client.get(
            f"{self.api_prefix}/users/me",
            headers=self._get_headers(token=access_token),
        )
        if resp.status_code == 401:
            raise AuthenticationError("Invalid or expired token")
        if resp.status_code != 200:
            raise AaaSException(f"Failed to fetch profile: {resp.text}")
        return resp.json()

    async def check_health(self) -> Dict[str, Any]:
        """Query platform readiness probe."""
        client = await self.get_client()
        resp = await client.get("/health/ready")
        return resp.json()
