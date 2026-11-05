"""Health and Diagnostics API Router (Layer 5: API).

Provides Kubernetes/Docker liveness, readiness, and observability metrics probes.
"""

import sys
import time
from datetime import datetime, timezone
from typing import Any, Dict
from fastapi import APIRouter, Response, status
from sqlalchemy import text
from auth_service.config import settings
from auth_service.storage.postgres.database import engine
from auth_service.storage.redis.client import get_redis_client


router = APIRouter(prefix="/health", tags=["Health & Diagnostics"])

_START_TIME = time.time()


@router.get(
    "",
    summary="Liveness Probe",
    description="Basic liveness check verifying the HTTP process is operational.",
)
async def liveness() -> Dict[str, Any]:
    return {
        "status": "ok",
        "app": settings.APP_NAME,
        "version": settings.APP_VERSION,
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }


@router.get(
    "/ready",
    summary="Readiness Probe",
    description="Probes connectivity to PostgreSQL and Redis subsystems.",
)
async def readiness(response: Response) -> Dict[str, Any]:
    checks = {
        "database": "unknown",
        "redis": "unknown",
    }
    healthy = True

    # Check Database Connectivity
    try:
        async with engine.connect() as conn:
            await conn.execute(text("SELECT 1"))
        checks["database"] = "healthy"
    except Exception as e:
        checks["database"] = f"unhealthy: {str(e)}"
        healthy = False

    # Check Redis Connectivity
    try:
        redis = await get_redis_client()
        await redis.ping()
        checks["redis"] = "healthy"
    except Exception as e:
        checks["redis"] = f"degraded: {str(e)}"
        # Redis in-memory fallback will report healthy

    overall_status = "healthy" if healthy else "degraded"
    if not healthy:
        response.status_code = status.HTTP_503_SERVICE_UNAVAILABLE

    return {
        "status": overall_status,
        "checks": checks,
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }


@router.get(
    "/metrics",
    summary="Observability & Performance Counters",
    description="Returns process runtime telemetry, uptime, and system metadata.",
)
async def metrics() -> Dict[str, Any]:
    uptime_seconds = int(time.time() - _START_TIME)
    return {
        "uptime_seconds": uptime_seconds,
        "python_version": sys.version,
        "app_env": settings.APP_ENV,
        "multi_tenancy": settings.MULTI_TENANCY_ENABLED,
        "rate_limiting": settings.RATE_LIMIT_ENABLED,
    }

