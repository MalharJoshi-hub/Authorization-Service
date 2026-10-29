"""Structured Access Request Logging Middleware (Layer 5: API).

Logs incoming HTTP requests, response status codes, latencies, and client IP addresses
in structured JSON format for telemetry and log aggregation pipelines.
"""

import time
from starlette.middleware.base import BaseHTTPMiddleware, RequestResponseEndpoint
from starlette.requests import Request
from starlette.responses import Response
from auth_service.core.logger import logger
from auth_service.core.security.rate_limiter import get_client_ip


class RequestLoggerMiddleware(BaseHTTPMiddleware):
    """Measures execution duration and logs request transactions."""

    async def dispatch(self, request: Request, call_next: RequestResponseEndpoint) -> Response:
        start_time = time.perf_counter()
        ip = get_client_ip(request)
        method = request.method
        path = request.url.path

        try:
            response = await call_next(request)
            duration_ms = (time.perf_counter() - start_time) * 1000

            # Skip health check log spam if desired
            if not path.startswith("/health"):
                logger.info(
                    f"{method} {path} - {response.status_code} ({duration_ms:.2f}ms) [{ip}]"
                )

            return response
        except Exception as e:
            duration_ms = (time.perf_counter() - start_time) * 1000
            logger.error(
                f"{method} {path} - FAILED ({duration_ms:.2f}ms) [{ip}]: {str(e)}"
            )
            raise
