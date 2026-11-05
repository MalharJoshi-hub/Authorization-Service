"""API Integration Tests for Permissions Discovery (Phase 8: Layer 5)."""

import pytest
from httpx import AsyncClient


@pytest.mark.asyncio
async def test_list_permissions(async_client: AsyncClient, admin_headers: dict):
    response = await async_client.get("/api/v1/permissions", headers=admin_headers)
    assert response.status_code == 200
    perms = response.json()
    assert len(perms) >= 1
    perm_names = [p["name"] for p in perms]
    assert "users:read" in perm_names
    assert "admin:*" in perm_names


@pytest.mark.asyncio
async def test_create_permission(async_client: AsyncClient, admin_headers: dict):
    payload = {
        "name": "invoices:generate",
        "resource": "invoices",
        "action": "generate",
        "description": "Generate monthly invoices",
    }
    response = await async_client.post("/api/v1/permissions", json=payload, headers=admin_headers)
    assert response.status_code == 201
    data = response.json()
    assert data["name"] == "invoices:generate"

