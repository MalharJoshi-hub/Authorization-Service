"""Request Correlation ID Middleware (Layer 5: API).

Extracts or generates an RFC-compliant UUID4 correlation identifier, attaches it
to context variables for log propagation, and returns it in the X-Request-ID header.
"""

import uuid
from starlette.middleware.base import BaseHTTPMiddleware, RequestResponseEndpoint
from starlette.requests import Request
from starlette.responses import Response
from auth_service.core.logger import request_id_ctx


class RequestIdMiddleware(BaseHTTPMiddleware):
    """Correlation ID propagation middleware."""

    async def dispatch(self, request: Request, call_next: RequestResponseEndpoint) -> Response:
        # Check if caller supplied correlation ID, else generate fresh UUID4
        request_id = request.headers.get("X-Request-ID")
        if not request_id:
            request_id = str(uuid.uuid4())

        # Store in context variable for asynchronous logging
        token = request_id_ctx.set(request_id)
        request.state.request_id = request_id

        try:
            response = await call_next(request)
            response.headers["X-Request-ID"] = request_id
            return response
        finally:
            request_id_ctx.reset(token)
