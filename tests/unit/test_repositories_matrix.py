"""Comprehensive database repositories matrix tests."""

import pytest
from datetime import datetime, timedelta, timezone

from auth_service.models.user import User
from auth_service.models.tenant import Tenant
from auth_service.models.role import Role
from auth_service.models.permission import Permission
from auth_service.models.api_key import APIKey
from auth_service.storage.postgres.user_repo import UserRepository
from auth_service.storage.postgres.tenant_repo import TenantRepository
from auth_service.storage.postgres.role_repo import RoleRepository
from auth_service.storage.postgres.permission_repo import PermissionRepository
from auth_service.storage.postgres.api_key_repo import APIKeyRepository
from auth_service.storage.postgres.audit_log_repo import AuditLogRepository
from auth_service.storage.postgres.session_repo import SessionRepository


@pytest.mark.asyncio
async def test_tenant_repo_lifecycle(db_session):
    repo = TenantRepository(db_session)
    t = await repo.create(name="Matrix Tenant", slug="matrix-tenant", plan="pro")
    assert t.id is not None
    assert t.slug == "matrix-tenant"

    fetched = await repo.get_by_id(t.id)
    assert fetched is not None
    assert fetched.name == "Matrix Tenant"

    by_slug = await repo.get_by_slug("matrix-tenant")
    assert by_slug is not None
    assert by_slug.id == t.id


@pytest.mark.asyncio
async def test_permission_repo_lifecycle(db_session):
    repo = PermissionRepository(db_session)
    p = await repo.create(name="matrix:read", resource="matrix", action="read", description="Matrix read perm")
    assert p.id is not None
    assert p.name == "matrix:read"

    fetched = await repo.get_by_name("matrix:read")
    assert fetched is not None
    assert fetched.resource == "matrix"


@pytest.mark.asyncio
async def test_role_repo_lifecycle(db_session, test_tenant):
    perm_repo = PermissionRepository(db_session)
    p1 = await perm_repo.create(name="item:create", resource="item", action="create")

    role_repo = RoleRepository(db_session)
    r = await role_repo.create(name="matrix_manager", tenant_id=test_tenant.id, description="Manager role")
    assert r.id is not None
    assert r.name == "matrix_manager"

    # Assign permission
    await role_repo.assign_permission(r.id, p1.id)
    refreshed = await role_repo.get_by_id(r.id)
    perm_names = [p.name for p in refreshed.permissions]
    assert "item:create" in perm_names


@pytest.mark.asyncio
async def test_user_repo_crud_matrix(db_session, test_tenant):
    repo = UserRepository(db_session)
    email = "matrix_user@test.org"

    # Create
    user = await repo.create(
        email=email,
        hashed_password="bcrypt_hashed_pwd",
        full_name="Matrix User",
        tenant_id=test_tenant.id,
    )
    assert user.id is not None
    assert user.email == email

    # Get by ID
    by_id = await repo.get_by_id(user.id)
    assert by_id is not None
    assert by_id.full_name == "Matrix User"

    # Get by email
    by_email = await repo.get_by_email(email, tenant_id=test_tenant.id)
    assert by_email is not None
    assert by_email.id == user.id

    # Update
    updated = await repo.update(user.id, full_name="Matrix Updated")
    assert updated.full_name == "Matrix Updated"

    # Pagination list
    users, total = await repo.list_users(tenant_id=test_tenant.id, skip=0, limit=10)
    assert total >= 1
    assert any(u.id == user.id for u in users)


@pytest.mark.asyncio
async def test_api_key_repo_lifecycle(db_session, test_tenant, test_user):
    repo = APIKeyRepository(db_session)
    key = await repo.create(
        tenant_id=test_tenant.id,
        user_id=test_user.id,
        name="Matrix Backend Service",
        prefix="aas_live_mx1234",
        key_hash="matrix_key_hash_value_99",
        scopes=["read:data"],
    )
    assert key.id is not None
    assert key.prefix == "aas_live_mx1234"

    fetched = await repo.get_by_key_hash("matrix_key_hash_value_99")
    assert fetched is not None
    assert fetched.name == "Matrix Backend Service"

    # Revoke
    revoked = await repo.revoke(key.id)
    assert revoked.is_active is False


@pytest.mark.asyncio
async def test_audit_log_repo_recording(db_session, test_tenant, test_user):
    repo = AuditLogRepository(db_session)
    log = await repo.record(
        tenant_id=test_tenant.id,
        user_id=test_user.id,
        event_type="test.event",
        status="success",
        ip_address="10.10.10.10",
        details={"info": "matrix test"},
    )
    assert log.id is not None

    logs, total = await repo.list_logs(tenant_id=test_tenant.id, user_id=test_user.id)
    assert total >= 1
    assert any(l.id == log.id for l in logs)


@pytest.mark.asyncio
async def test_session_repo_lifecycle(db_session, test_tenant, test_user):
    repo = SessionRepository(db_session)
    now = datetime.now(timezone.utc)
    sess = await repo.create(
        user_id=test_user.id,
        tenant_id=test_tenant.id,
        device_name="Matrix Browser",
        device_fingerprint="fp_matrix_123",
        ip_address="127.0.0.1",
        expires_at=now + timedelta(hours=2),
    )
    assert sess.id is not None
    assert sess.is_active is True

    active_sessions = await repo.list_active_by_user(test_user.id)
    assert any(s.id == sess.id for s in active_sessions)

    # Deactivate session
    await repo.deactivate(sess.id)
    refreshed = await repo.get_by_id(sess.id)
    assert refreshed.is_active is False

