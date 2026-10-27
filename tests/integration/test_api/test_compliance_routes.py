"""Integration tests for GDPR/CCPA compliance and privacy routes."""

import pytest
from httpx import AsyncClient


@pytest.mark.asyncio
async def test_compliance_export_route(async_client: AsyncClient, auth_headers: dict):
    resp = await async_client.get("/api/v1/compliance/export", headers=auth_headers)
    assert resp.status_code == 200
    data = resp.json()

    assert "metadata" in data
    assert "profile" in data
    assert "sessions" in data
    assert "recent_audit_events" in data
    assert "sha256_checksum" in data["metadata"]


@pytest.mark.asyncio
async def test_compliance_forget_me_route(async_client: AsyncClient, auth_headers: dict):
    resp = await async_client.post("/api/v1/compliance/forget-me", headers=auth_headers)
    assert resp.status_code == 200
    data = resp.json()

    assert data["status"] == "success"
    assert "pseudonymized_id" in data
    assert "erased_at" in data
