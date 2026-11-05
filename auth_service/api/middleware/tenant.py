"""Multi-Tenant Context Resolution Middleware (Layer 5: API).

Resolves tenant context from HTTP headers (X-Tenant-ID) or Host header subdomains,
attaching the resolved tenant identifier to request.state and contextvars.
"""

from starlette.middleware.base import BaseHTTPMiddleware, RequestResponseEndpoint
from starlette.requests import Request
from starlette.responses import Response
from auth_service.config import settings
from auth_service.core.logger import tenant_id_ctx


class TenantResolutionMiddleware(BaseHTTPMiddleware):
    """Resolves and injects tenant scope into the execution context."""

    async def dispatch(self, request: Request, call_next: RequestResponseEndpoint) -> Response:
        tenant_id = request.headers.get("X-Tenant-ID")

        if not tenant_id:
            # Fallback to subdomain extraction if enabled
            host = request.headers.get("host", "")
            parts = host.split(".")
            if len(parts) > 2 and parts[0] not in ("www", "api", "auth", "localhost"):
                tenant_id = parts[0]

        if not tenant_id:
            tenant_id = settings.DEFAULT_TENANT_ID

        request.state.tenant_id = tenant_id
        token = tenant_id_ctx.set(tenant_id)

        try:
            return await call_next(request)
        finally:
            tenant_id_ctx.reset(token)

