"""Prometheus metrics exposition endpoint."""

from __future__ import annotations

from fastapi import APIRouter, Response

from auth_service.core.telemetry import telemetry

router = APIRouter(tags=["Metrics"])


@router.get("/metrics", response_class=Response)
async def get_prometheus_metrics() -> Response:
    """Expose application metrics in standard Prometheus exposition text format."""
    metrics_text = telemetry.export_prometheus()
    return Response(content=metrics_text, media_type="text/plain; version=0.0.4; charset=utf-8")
