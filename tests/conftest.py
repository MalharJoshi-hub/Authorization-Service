"""Pytest Shared Fixture Definitions & Testing Harness (Phase 8).

Configures an isolated in-memory test database, async HTTP client, and baseline entities.
"""

import asyncio
from typing import AsyncGenerator
import pytest
import pytest_asyncio
from httpx import AsyncClient, ASGITransport
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine
from auth_service.config import settings
from auth_service.models.base import Base
from auth_service.models.tenant import Tenant
from auth_service.models.user import User
from auth_service.models.role import Role
from auth_service.models.permission import Permission
from auth_service.core.rbac.permissions import ALL_SYSTEM_PERMISSIONS
from auth_service.core.security.password import hash_password
from auth_service.core.security.jwt_handler import create_access_token
from auth_service.core.dependencies import get_db
from auth_service.storage.postgres.database import get_db as prod_get_db
from auth_service.main import app


# Dedicated in-memory SQLite engine for tests
TEST_DB_URL = "sqlite+aiosqlite:///:memory:"

# Disable rate limiting for API test runner throughput
settings.RATE_LIMIT_ENABLED = False

test_engine = create_async_engine(
    TEST_DB_URL,
    connect_args={"check_same_thread": False},
)

test_session_factory = async_sessionmaker(
    bind=test_engine,
    class_=AsyncSession,
    expire_on_commit=False,
    autoflush=False,
)


@pytest_asyncio.fixture(scope="session", autouse=True)
async def setup_test_database():
    """Create all schema tables once for the test session."""
    async with test_engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    yield
    async with test_engine.begin() as conn:
        await conn.run_sync(Base.metadata.drop_all)
    await test_engine.dispose()


@pytest_asyncio.fixture
async def db_session() -> AsyncGenerator[AsyncSession, None]:
    """Provide an isolated database session for a test with rollback."""
    async with test_session_factory() as session:
        yield session
        await session.rollback()


@pytest_asyncio.fixture
async def async_client(db_session: AsyncSession) -> AsyncGenerator[AsyncClient, None]:
    """Provide an AsyncClient wired with dependency override to the test DB."""
    async def override_get_db():
        yield db_session

    app.dependency_overrides[prod_get_db] = override_get_db
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        yield client
    app.dependency_overrides.clear()


@pytest_asyncio.fixture
async def test_tenant(db_session: AsyncSession) -> Tenant:
    """Fixture ensuring a default tenant exists."""
    tenant = await db_session.get(Tenant, settings.DEFAULT_TENANT_ID)
    if not tenant:
        tenant = Tenant(
            id=settings.DEFAULT_TENANT_ID,
            name="Test Organization",
            slug="test-org",
            plan="enterprise",
            is_active=True,
        )
        db_session.add(tenant)
        await db_session.commit()
    return tenant


@pytest_asyncio.fixture
async def standard_permissions(db_session: AsyncSession) -> list:
    """Ensure standard system permissions exist in test DB."""
    from sqlalchemy import select
    res = await db_session.execute(select(Permission))
    perms = list(res.scalars().all())
    if not perms:
        for pdef in ALL_SYSTEM_PERMISSIONS:
            p = Permission(
                name=pdef.name,
                resource=pdef.resource,
                action=pdef.action,
                description=pdef.description,
            )
            db_session.add(p)
        await db_session.commit()
        res = await db_session.execute(select(Permission))
        perms = list(res.scalars().all())
    return perms


@pytest_asyncio.fixture
async def admin_role(db_session: AsyncSession, test_tenant: Tenant, standard_permissions: list) -> Role:
    """Fixture ensuring an admin role with all permissions exists."""
    from sqlalchemy import select
    stmt = select(Role).where(Role.tenant_id == test_tenant.id, Role.name == "admin")
    res = await db_session.execute(stmt)
    role = res.scalar_one_or_none()
    if not role:
        role = Role(
            tenant_id=test_tenant.id,
            name="admin",
            description="Full administrator",
            is_system=True,
        )
        role.permissions = standard_permissions
        db_session.add(role)
        await db_session.commit()
    return role


@pytest_asyncio.fixture
async def member_role(db_session: AsyncSession, test_tenant: Tenant, standard_permissions: list) -> Role:
    """Fixture ensuring a standard member role exists."""
    from sqlalchemy import select
    stmt = select(Role).where(Role.tenant_id == test_tenant.id, Role.name == "member")
    res = await db_session.execute(stmt)
    role = res.scalar_one_or_none()
    if not role:
        member_perms = [p for p in standard_permissions if p.action in ("read",)]
        role = Role(
            tenant_id=test_tenant.id,
            name="member",
            description="Standard member",
            is_system=True,
        )
        role.permissions = member_perms
        db_session.add(role)
        await db_session.commit()
    return role


@pytest_asyncio.fixture
async def test_user(db_session: AsyncSession, test_tenant: Tenant, member_role: Role) -> User:
    """Fixture providing a standard verified active user."""
    from sqlalchemy import select
    email = "test.user@example.com"
    stmt = select(User).where(User.tenant_id == test_tenant.id, User.email == email)
    res = await db_session.execute(stmt)
    user = res.scalar_one_or_none()
    if not user:
        user = User(
            tenant_id=test_tenant.id,
            email=email,
            hashed_password=hash_password("UserPassword123!@"),
            full_name="Standard Test User",
            is_active=True,
            is_verified=True,
            is_superuser=False,
        )
        user.roles = [member_role]
        db_session.add(user)
        await db_session.commit()
    return user


@pytest_asyncio.fixture
async def test_admin(db_session: AsyncSession, test_tenant: Tenant, admin_role: Role) -> User:
    """Fixture providing an active administrator user."""
    from sqlalchemy import select
    email = "test.admin@example.com"
    stmt = select(User).where(User.tenant_id == test_tenant.id, User.email == email)
    res = await db_session.execute(stmt)
    admin = res.scalar_one_or_none()
    if not admin:
        admin = User(
            tenant_id=test_tenant.id,
            email=email,
            hashed_password=hash_password("AdminPassword123!@"),
            full_name="Admin Test User",
            is_active=True,
            is_verified=True,
            is_superuser=True,
        )
        admin.roles = [admin_role]
        db_session.add(admin)
        await db_session.commit()
    return admin


@pytest_asyncio.fixture
def auth_headers(test_user: User) -> dict:
    """Authorization headers for test_user."""
    token = create_access_token(
        user_id=test_user.id,
        email=test_user.email,
        tenant_id=test_user.tenant_id,
        roles=[r.name for r in test_user.roles],
        permissions=[p.name for r in test_user.roles for p in r.permissions],
    )
    return {
        "Authorization": f"Bearer {token}",
        "X-Tenant-ID": test_user.tenant_id,
    }


@pytest_asyncio.fixture
def admin_headers(test_admin: User) -> dict:
    """Authorization headers for test_admin."""
    token = create_access_token(
        user_id=test_admin.id,
        email=test_admin.email,
        tenant_id=test_admin.tenant_id,
        roles=[r.name for r in test_admin.roles],
        permissions=[p.name for r in test_admin.roles for p in r.permissions],
    )
    return {
        "Authorization": f"Bearer {token}",
        "X-Tenant-ID": test_admin.tenant_id,
    }
