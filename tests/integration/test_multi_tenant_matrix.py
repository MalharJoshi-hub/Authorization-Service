"""Comprehensive Multi-Tenant Isolation Matrix Integration Tests."""

import uuid
import pytest
from httpx import AsyncClient
from sqlalchemy import select
from auth_service.core.security.jwt_handler import create_access_token
from auth_service.models.user import User
from auth_service.models.tenant import Tenant
from auth_service.models.role import Role
from auth_service.models.permission import Permission
from auth_service.models.api_key import APIKey


@pytest.mark.asyncio
async def test_multi_tenant_user_isolation(async_client: AsyncClient, db_session):
    uid = uuid.uuid4().hex[:8]
    # Setup Tenant Alpha
    t_alpha = Tenant(name="Alpha Org", slug=f"alpha-org-{uid}", plan="standard", is_active=True, settings_json="{}")
    # Setup Tenant Beta
    t_beta = Tenant(name="Beta Org", slug=f"beta-org-{uid}", plan="standard", is_active=True, settings_json="{}")
    db_session.add_all([t_alpha, t_beta])
    await db_session.flush()

    user_alpha = User(email=f"user_{uid}@alpha.com", tenant_id=t_alpha.id, is_active=True, is_verified=True)
    user_beta = User(email=f"user_{uid}@beta.com", tenant_id=t_beta.id, is_active=True, is_verified=True)
    db_session.add_all([user_alpha, user_beta])
    await db_session.commit()

    token_alpha = create_access_token(
        user_id=user_alpha.id,
        email=user_alpha.email,
        tenant_id=t_alpha.id,
        roles=["admin"],
        permissions=["read:users", "write:users"],
    )

    headers_alpha = {
        "Authorization": f"Bearer {token_alpha}",
        "X-Tenant-ID": t_alpha.id,
    }

    # Tenant Alpha attempts to access Tenant Beta's user by ID
    resp = await async_client.get(f"/api/v1/users/{user_beta.id}", headers=headers_alpha)
    # Must be 404 Not Found or 403 Forbidden, NEVER leak user details
    assert resp.status_code in (403, 404)


@pytest.mark.asyncio
async def test_multi_tenant_api_key_isolation(async_client: AsyncClient, db_session):
    uid = uuid.uuid4().hex[:8]
    t_alpha = Tenant(name="Alpha Org 2", slug=f"alpha-org-2-{uid}", plan="standard", is_active=True, settings_json="{}")
    t_beta = Tenant(name="Beta Org 2", slug=f"beta-org-2-{uid}", plan="standard", is_active=True, settings_json="{}")
    db_session.add_all([t_alpha, t_beta])
    await db_session.flush()

    # Reuse permission if already created by another test
    perm_res = await db_session.execute(select(Permission).where(Permission.name == "api_keys:read"))
    perm = perm_res.scalar_one_or_none()
    if not perm:
        perm = Permission(name="api_keys:read", resource="api_keys", action="read")
        db_session.add(perm)
        await db_session.flush()

    role = Role(name=f"admin_{uid}", tenant_id=t_alpha.id, permissions=[perm])
    user_alpha = User(id=f"admin-alpha-{uid}", email=f"admin_{uid}@alpha.com", tenant_id=t_alpha.id, is_active=True, is_verified=True, roles=[role])
    key_alpha = APIKey(tenant_id=t_alpha.id, name="Alpha Key", prefix=f"aas_{uid[:4]}", key_hash=f"hash_alp_{uid}", is_active=True)
    key_beta = APIKey(tenant_id=t_beta.id, name="Beta Key", prefix=f"aas_{uid[4:]}", key_hash=f"hash_bet_{uid}", is_active=True)
    db_session.add_all([role, user_alpha, key_alpha, key_beta])
    await db_session.commit()

    token_alpha = create_access_token(
        user_id=f"admin-alpha-{uid}",
        email=f"admin_{uid}@alpha.com",
        tenant_id=t_alpha.id,
        roles=["admin"],
        permissions=["api_keys:read"],
    )
    headers_alpha = {
        "Authorization": f"Bearer {token_alpha}",
        "X-Tenant-ID": t_alpha.id,
    }

    resp = await async_client.get("/api/v1/api-keys", headers=headers_alpha)
    assert resp.status_code == 200
    keys_listed = resp.json()
    assert all(k.get("tenant_id") == t_alpha.id for k in keys_listed if isinstance(k, dict))
