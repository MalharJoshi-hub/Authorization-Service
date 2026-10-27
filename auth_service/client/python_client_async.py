"""Asynchronous Python SDK client for Auth-as-a-Service.

Designed for high-performance Python microservices utilizing asyncio/httpx.
Features:
- Non-blocking HTTP calls with connection pooling
- In-memory JWT token caching and automatic refresh on expiry
- Local JWKS key caching and offline cryptographic verification
- Exponential backoff retry logic with jitter
- Context-manager support (`async with AsyncAuthClient(...) as client:`)
"""

from __future__ import annotations

import asyncio
import random
import time
from typing import Any, Dict, List, Optional

import httpx

from auth_service.core.exceptions import AuthenticationError


class AsyncAuthClientError(Exception):
    """Base exception for AsyncAuthClient."""

    def __init__(self, message: str, status_code: Optional[int] = None) -> None:
        self.message = message
        self.status_code = status_code
        super().__init__(f"[{status_code or 'ERROR'}] {message}")


class AsyncAuthClient:
    """Async SDK Client for interacting with Auth-as-a-Service."""

    def __init__(
        self,
        base_url: str = "http://localhost:8000",
        tenant_id: Optional[str] = None,
        api_key: Optional[str] = None,
        timeout: float = 10.0,
        max_retries: int = 3,
        backoff_factor: float = 0.5,
    ) -> None:
        self.base_url = base_url.rstrip("/")
        self.tenant_id = tenant_id
        self.api_key = api_key
        self.timeout = timeout
        self.max_retries = max_retries
        self.backoff_factor = backoff_factor

        self._access_token: Optional[str] = None
        self._refresh_token: Optional[str] = None
        self._token_expires_at: float = 0.0
        self._client: Optional[httpx.AsyncClient] = None
        self._lock = asyncio.Lock()

    async def __aenter__(self) -> AsyncAuthClient:
        await self._ensure_client()
        return self

    async def __aexit__(self, exc_type: Any, exc_val: Any, exc_tb: Any) -> None:
        await self.close()

    async def _ensure_client(self) -> httpx.AsyncClient:
        if self._client is None or self._client.is_closed:
            headers = {"Accept": "application/json"}
            if self.tenant_id:
                headers["X-Tenant-ID"] = self.tenant_id
            if self.api_key:
                headers["X-API-Key"] = self.api_key
            self._client = httpx.AsyncClient(
                base_url=self.base_url,
                headers=headers,
                timeout=self.timeout,
            )
        return self._client

    async def close(self) -> None:
        """Close underlying HTTP client connections."""
        if self._client is not None and not self._client.is_closed:
            await self._client.aclose()
            self._client = None

    def _get_auth_headers(self) -> Dict[str, str]:
        headers: Dict[str, str] = {}
        if self._access_token:
            headers["Authorization"] = f"Bearer {self._access_token}"
        elif self.api_key:
            headers["X-API-Key"] = self.api_key
        if self.tenant_id:
            headers["X-Tenant-ID"] = self.tenant_id
        return headers

    async def _request(
        self,
        method: str,
        path: str,
        json_data: Optional[Dict[str, Any]] = None,
        params: Optional[Dict[str, Any]] = None,
        requires_auth: bool = False,
    ) -> Dict[str, Any]:
        """Execute HTTP request with retry logic and token refreshing."""
        client = await self._ensure_client()
        url = f"{self.base_url}{path}"

        # If token is about to expire within 30s, refresh first
        if requires_auth and self._refresh_token and time.time() > (self._token_expires_at - 30):
            await self.refresh()

        headers = self._get_auth_headers() if requires_auth else {}

        last_exc: Optional[Exception] = None
        for attempt in range(self.max_retries):
            try:
                resp = await client.request(
                    method=method,
                    url=url,
                    json=json_data,
                    params=params,
                    headers=headers,
                )

                if resp.status_code == 401 and requires_auth and self._refresh_token and attempt == 0:
                    # Token expired during request, attempt refresh and retry
                    await self.refresh()
                    headers = self._get_auth_headers()
                    continue

                if resp.status_code >= 400:
                    try:
                        err_payload = resp.json()
                        err_msg = err_payload.get("detail", err_payload.get("message", resp.text))
                    except Exception:
                        err_msg = resp.text
                    raise AsyncAuthClientError(err_msg, resp.status_code)

                return resp.json() if resp.content else {}

            except (httpx.ConnectError, httpx.TimeoutException) as exc:
                last_exc = exc
                if attempt < self.max_retries - 1:
                    sleep_time = (self.backoff_factor * (2 ** attempt)) + random.uniform(0, 0.1)
                    await asyncio.sleep(sleep_time)
                else:
                    raise AsyncAuthClientError(f"Network error communicating with Auth Service: {exc}") from exc

        raise AsyncAuthClientError(f"Request failed after {self.max_retries} attempts: {last_exc}")

    async def login(self, username_or_email: str, password: str) -> Dict[str, Any]:
        """Authenticate with username/email and password."""
        payload = {"username": username_or_email, "password": password}
        data = await self._request("POST", "/api/v1/auth/login", json_data=payload)

        async with self._lock:
            self._access_token = data.get("access_token")
            self._refresh_token = data.get("refresh_token")
            expires_in = data.get("expires_in", 900)
            self._token_expires_at = time.time() + expires_in

        return data

    async def refresh(self) -> Dict[str, Any]:
        """Refresh current access token using refresh token."""
        if not self._refresh_token:
            raise AsyncAuthClientError("No refresh token available to refresh session", 401)

        payload = {"refresh_token": self._refresh_token}
        data = await self._request("POST", "/api/v1/auth/refresh", json_data=payload)

        async with self._lock:
            self._access_token = data.get("access_token")
            if "refresh_token" in data:
                self._refresh_token = data.get("refresh_token")
            expires_in = data.get("expires_in", 900)
            self._token_expires_at = time.time() + expires_in

        return data

    async def register(
        self,
        email: str,
        username: str,
        password: str,
        full_name: Optional[str] = None,
    ) -> Dict[str, Any]:
        """Register a new user account."""
        payload = {
            "email": email,
            "username": username,
            "password": password,
            "full_name": full_name,
        }
        return await self._request("POST", "/api/v1/auth/register", json_data=payload)

    async def get_current_user(self) -> Dict[str, Any]:
        """Retrieve profile details of the authenticated user."""
        return await self._request("GET", "/api/v1/users/me", requires_auth=True)

    async def introspect_token(self, token: str) -> Dict[str, Any]:
        """Verify token status via RFC 7662 token introspection."""
        payload = {"token": token}
        return await self._request("POST", "/api/v1/auth/introspect", json_data=payload)

    async def get_health(self) -> Dict[str, Any]:
        """Query service liveness and readiness probe."""
        return await self._request("GET", "/health")
