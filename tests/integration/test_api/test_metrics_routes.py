"""Integration tests for Prometheus metrics router."""

import pytest
from httpx import AsyncClient


@pytest.mark.asyncio
async def test_get_metrics_endpoint(async_client: AsyncClient):
    resp = await async_client.get("/metrics")
    assert resp.status_code == 200
    assert "text/plain" in resp.headers["content-type"]

    body = resp.text
    assert "# HELP auth_logins_total" in body
    assert "# TYPE auth_logins_total counter" in body
    assert "# HELP auth_active_sessions_gauge" in body
