"""End-to-End Test: Multi-Tenant Data Isolation Enforcement (Phase 8)."""

import pytest
from httpx import AsyncClient
from sqlalchemy.ext.asyncio import AsyncSession
from auth_service.models.tenant import Tenant
from auth_service.models.user import User
from auth_service.core.security.jwt_handler import create_access_token


@pytest.mark.asyncio
async def test_multi_tenant_boundary_isolation(
    async_client: AsyncClient, db_session: AsyncSession, test_admin: User
):
    # 1. Provision two separate organizations
    org_a = Tenant(
        id="11111111-1111-1111-1111-111111111111",
        name="Organization Alpha",
        slug="alpha-org",
        plan="standard",
        is_active=True,
    )
    org_b = Tenant(
        id="22222222-2222-2222-2222-222222222222",
        name="Organization Beta",
        slug="beta-org",
        plan="standard",
        is_active=True,
    )
    db_session.add(org_a)
    db_session.add(org_b)
    await db_session.commit()

    # 2. Register user in Organization Alpha
    await async_client.post(
        "/api/v1/auth/register",
        json={
            "email": "user@alpha.com",
            "password": "PasswordAlpha123!@",
            "tenant_id": org_a.id,
        },
    )

    # 3. Attempt to authenticate user@alpha.com under Organization Beta -> must fail
    login_cross_tenant = await async_client.post(
        "/api/v1/auth/login",
        json={
            "email": "user@alpha.com",
            "password": "PasswordAlpha123!@",
            "tenant_id": org_b.id,
        },
    )
    assert login_cross_tenant.status_code == 401

    # 4. Alpha admin cannot see Beta users
    from auth_service.models.role import Role
    from auth_service.models.permission import Permission
    from sqlalchemy import select

    res = await db_session.execute(select(Permission).where(Permission.name == "users:manage"))
    manage_perm = res.scalar_one_or_none()
    if not manage_perm:
        manage_perm = Permission(name="users:manage", resource="users", action="manage")
        db_session.add(manage_perm)

    admin_role_alpha = Role(
        tenant_id=org_a.id,
        name="admin",
        description="Alpha Admin",
        is_system=True,
    )
    admin_role_alpha.permissions = [manage_perm]
    db_session.add(admin_role_alpha)

    admin_alpha = User(
        id="admin-alpha-id",
        tenant_id=org_a.id,
        email="admin@alpha.com",
        full_name="Alpha Admin",
        is_active=True,
        is_verified=True,
        is_superuser=True,
    )
    admin_alpha.roles = [admin_role_alpha]
    db_session.add(admin_alpha)
    await db_session.commit()

    alpha_admin_token = create_access_token(
        user_id=admin_alpha.id,
        email=admin_alpha.email,
        tenant_id=org_a.id,
        roles=["admin"],
        permissions=["users:manage"],
    )
    alpha_headers = {
        "Authorization": f"Bearer {alpha_admin_token}",
        "X-Tenant-ID": org_a.id,
    }

    list_resp = await async_client.get("/api/v1/admin/users", headers=alpha_headers)
    assert list_resp.status_code == 200
    for u in list_resp.json()["items"]:
        assert u["tenant_id"] == org_a.id
        assert u["tenant_id"] != org_b.id
