"""API Integration Tests for RBAC Role Management (Phase 8: Layer 5)."""

import pytest
from httpx import AsyncClient
from auth_service.models.tenant import Tenant


@pytest.mark.asyncio
async def test_list_roles_with_admin_privilege(
    async_client: AsyncClient, test_tenant: Tenant, admin_headers: dict
):
    response = await async_client.get("/api/v1/roles", headers=admin_headers)
    assert response.status_code == 200
    roles = response.json()
    assert len(roles) >= 1
    role_names = [r["name"] for r in roles]
    assert "admin" in role_names


@pytest.mark.asyncio
async def test_create_custom_role(
    async_client: AsyncClient, test_tenant: Tenant, admin_headers: dict
):
    payload = {
        "name": "billing_specialist",
        "description": "Manages billing invoices",
        "permission_names": ["users:read"],
    }
    response = await async_client.post("/api/v1/roles", json=payload, headers=admin_headers)
    assert response.status_code == 201
    data = response.json()
    assert data["name"] == "billing_specialist"
    assert data["is_system"] is False

    role_id = data["id"]

    # Assign additional permission
    assign_resp = await async_client.post(
        f"/api/v1/roles/{role_id}/permissions",
        json={"permission_names": ["users:read", "audit:read"]},
        headers=admin_headers,
    )
    assert assign_resp.status_code == 200

    # Delete custom role
    del_resp = await async_client.delete(f"/api/v1/roles/{role_id}", headers=admin_headers)
    assert del_resp.status_code == 200


@pytest.mark.asyncio
async def test_member_cannot_create_roles_forbidden(
    async_client: AsyncClient, auth_headers: dict
):
    payload = {"name": "unauthorized_role"}
    response = await async_client.post("/api/v1/roles", json=payload, headers=auth_headers)
    assert response.status_code == 403

