"""Integration Tests for Database Repositories (Phase 8: Layer 4)."""

from datetime import datetime, timezone, timedelta
import pytest
from sqlalchemy.ext.asyncio import AsyncSession
from auth_service.storage.postgres.user_repo import UserRepository
from auth_service.storage.postgres.role_repo import RoleRepository
from auth_service.storage.postgres.permission_repo import PermissionRepository
from auth_service.storage.postgres.token_repo import TokenRepository
from auth_service.storage.postgres.api_key_repo import APIKeyRepository
from auth_service.storage.postgres.tenant_repo import TenantRepository
from auth_service.storage.postgres.audit_log_repo import AuditLogRepository
from auth_service.storage.postgres.oauth_repo import OAuthRepository
from auth_service.models.tenant import Tenant
from auth_service.core.security.password import hash_password
from auth_service.core.exceptions import ConflictError, ResourceNotFoundError


@pytest.mark.asyncio
async def test_user_repository_crud(db_session: AsyncSession, test_tenant: Tenant):
    repo = UserRepository(db_session)

    # 1. Create
    email = "integration.user@example.com"
    user = await repo.create(
        tenant_id=test_tenant.id,
        email=email,
        hashed_password=hash_password("Pass123!@"),
        full_name="Integration User",
    )
    assert user.id is not None
    assert user.email == email

    # Duplicate creation fails
    with pytest.raises(ConflictError):
        await repo.create(tenant_id=test_tenant.id, email=email)

    # 2. Get by email & ID
    by_email = await repo.get_by_email(test_tenant.id, email)
    assert by_email is not None
    assert by_email.id == user.id

    by_id = await repo.get_by_id(user.id, tenant_id=test_tenant.id)
    assert by_id is not None

    # 3. Update
    updated = await repo.update(user.id, full_name="Updated Name", is_verified=True)
    assert updated.full_name == "Updated Name"
    assert updated.is_verified is True

    # 4. List users
    users, total = await repo.list_users(tenant_id=test_tenant.id, limit=10)
    assert total >= 1
    assert any(u.id == user.id for u in users)

    # 5. Soft delete
    await repo.delete(user.id, tenant_id=test_tenant.id, soft_delete=True)
    deleted_user = await repo.get_by_id(user.id)
    assert deleted_user.is_active is False


@pytest.mark.asyncio
async def test_role_and_permission_repositories(db_session: AsyncSession, test_tenant: Tenant):
    role_repo = RoleRepository(db_session)
    perm_repo = PermissionRepository(db_session)

    # 1. Create custom permission
    perm = await perm_repo.create(
        name="custom:execute",
        resource="custom",
        action="execute",
        description="Run custom job",
    )
    assert perm.name == "custom:execute"

    # 2. Create custom role
    role = await role_repo.create(
        tenant_id=test_tenant.id,
        name="job_runner",
        description="Executes jobs",
        permissions=[perm],
    )
    assert role.name == "job_runner"
    assert len(role.permissions) == 1
    assert role.permissions[0].name == "custom:execute"

    # 3. Update role
    updated_role = await role_repo.update(role.id, test_tenant.id, description="Updated job runner description")
    assert updated_role.description == "Updated job runner description"

    # 4. Delete custom role
    deleted = await role_repo.delete(role.id, test_tenant.id)
    assert deleted is True


@pytest.mark.asyncio
async def test_token_repository_rotation(db_session: AsyncSession, test_tenant: Tenant):
    user_repo = UserRepository(db_session)
    token_repo = TokenRepository(db_session)

    user = await user_repo.create(
        tenant_id=test_tenant.id,
        email="token.repo@example.com",
    )

    fam_id = "family-uuid-1"
    token_hash = "tokenhash1234567890abcdef1234567890abcdef1234567890abcdef12345678"
    expires = datetime.now(timezone.utc) + timedelta(days=7)

    # Create refresh token record
    token_rec = await token_repo.create(
        user_id=user.id,
        tenant_id=test_tenant.id,
        token_hash=token_hash,
        family_id=fam_id,
        expires_at=expires,
    )
    assert token_rec.is_revoked is False

    # Lookup
    found = await token_repo.get_by_hash(token_hash)
    assert found is not None
    assert found.family_id == fam_id

    # Revoke individual
    await token_repo.revoke_token(token_rec.id)
    refreshed = await token_repo.get_by_hash(token_hash)
    assert refreshed.is_revoked is True


@pytest.mark.asyncio
async def test_api_key_repository(db_session: AsyncSession, test_tenant: Tenant):
    repo = APIKeyRepository(db_session)

    key_hash = "hashabcdef1234567890abcdef1234567890abcdef1234567890abcdef12345678"
    prefix = "aas_live_prefix1"

    key = await repo.create(
        tenant_id=test_tenant.id,
        name="Test Service Key",
        prefix=prefix,
        key_hash=key_hash,
        scopes=["read:users", "write:users"],
    )
    assert key.name == "Test Service Key"
    assert "read:users" in key.scopes

    # Lookup by hash
    found = await repo.get_by_hash(key_hash)
    assert found is not None

    # Revoke
    await repo.revoke(key.id, tenant_id=test_tenant.id)
    revoked = await repo.get_by_id(key.id)
    assert revoked.is_active is False


@pytest.mark.asyncio
async def test_audit_log_and_analytics_repo(db_session: AsyncSession, test_tenant: Tenant):
    repo = AuditLogRepository(db_session)

    # Log 3 events
    await repo.log(tenant_id=test_tenant.id, event_type="login", status="success")
    await repo.log(tenant_id=test_tenant.id, event_type="login", status="failed")
    await repo.log(tenant_id=test_tenant.id, event_type="register", status="success")

    logs, total = await repo.query(tenant_id=test_tenant.id)
    assert total >= 3

    # CSV export
    csv_str = await repo.export_csv(tenant_id=test_tenant.id)
    assert "Timestamp" in csv_str
    assert "login" in csv_str

    # Analytics summary
    summary = await repo.get_analytics_summary(tenant_id=test_tenant.id, days=7)
    assert summary["successful_logins"] >= 1
    assert summary["failed_logins"] >= 1
    assert summary["new_registrations"] >= 1


@pytest.mark.asyncio
async def test_oauth_repository(db_session: AsyncSession, test_tenant: Tenant):
    user_repo = UserRepository(db_session)
    oauth_repo = OAuthRepository(db_session)

    user = await user_repo.create(
        tenant_id=test_tenant.id,
        email="oauth.repo@example.com",
    )

    # Link account
    account = await oauth_repo.create_or_update(
        user_id=user.id,
        provider="github",
        provider_user_id="gh_987654",
        email=user.email,
        access_token="gh_token_123",
    )
    assert account.provider == "github"

    # Lookup
    found = await oauth_repo.get_by_provider("github", "gh_987654")
    assert found is not None
    assert found.user_id == user.id

    # Unlink
    unlinked = await oauth_repo.unlink(user.id, "github")
    assert unlinked is True

