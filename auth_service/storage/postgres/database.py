"""Async Database Engine, Session Factory, and Schema Seeder (Layer 4).

Supports high-performance asyncpg pool for PostgreSQL in production and aiosqlite
for development and testing. Manages session lifecycles and default seed fixtures.
"""

from typing import AsyncGenerator
from sqlalchemy.ext.asyncio import (
    AsyncEngine,
    AsyncSession,
    async_sessionmaker,
    create_async_engine,
)
from sqlalchemy import select
from auth_service.config import settings
from auth_service.core.logger import logger
from auth_service.models.base import Base
from auth_service.models.tenant import Tenant
from auth_service.models.role import Role
from auth_service.models.permission import Permission
from auth_service.core.rbac.permissions import ALL_SYSTEM_PERMISSIONS


def build_engine_kwargs():
    """Configure connection pooling options based on database backend."""
    kwargs = {
        "echo": settings.DB_ECHO,
        "future": True,
    }
    if settings.is_sqlite:
        kwargs["connect_args"] = {"check_same_thread": False}
    else:
        kwargs.update({
            "pool_size": settings.DB_POOL_SIZE,
            "max_overflow": settings.DB_MAX_OVERFLOW,
            "pool_timeout": settings.DB_POOL_TIMEOUT,
            "pool_pre_ping": True,
        })
    return kwargs


engine: AsyncEngine = create_async_engine(settings.DATABASE_URL, **build_engine_kwargs())

async_session_factory = async_sessionmaker(
    bind=engine,
    class_=AsyncSession,
    expire_on_commit=False,
    autoflush=False,
)


async def get_db() -> AsyncGenerator[AsyncSession, None]:
    """FastAPI async dependency supplying an isolated database session per request."""
    async with async_session_factory() as session:
        try:
            yield session
            await session.commit()
        except Exception:
            await session.rollback()
            raise
        finally:
            await session.close()


async def init_db() -> None:
    """Initialize database tables and seed baseline tenants, roles, and permissions."""
    async with engine.begin() as conn:
        # Create schema tables if not existing
        await conn.run_sync(Base.metadata.create_all)

    # Seed baseline fixtures
    async with async_session_factory() as session:
        try:
            # 1. Seed Default Tenant
            tenant_res = await session.execute(
                select(Tenant).where(Tenant.id == settings.DEFAULT_TENANT_ID)
            )
            tenant = tenant_res.scalar_one_or_none()
            if not tenant:
                tenant = Tenant(
                    id=settings.DEFAULT_TENANT_ID,
                    name=settings.DEFAULT_TENANT_NAME,
                    slug="default",
                    plan="enterprise",
                    is_active=True,
                )
                session.add(tenant)
                await session.flush()
                logger.info("Seeded default tenant organization")

            # 2. Seed System Permissions
            existing_perms_res = await session.execute(select(Permission.name))
            existing_perm_names = set(existing_perms_res.scalars().all())

            seeded_perms = []
            for pdef in ALL_SYSTEM_PERMISSIONS:
                if pdef.name not in existing_perm_names:
                    perm = Permission(
                        name=pdef.name,
                        resource=pdef.resource,
                        action=pdef.action,
                        description=pdef.description,
                    )
                    session.add(perm)
                    seeded_perms.append(perm)
                    existing_perm_names.add(pdef.name)

            if seeded_perms:
                await session.flush()
                logger.info(f"Seeded {len(seeded_perms)} standard permissions")

            # 3. Seed Default Roles for Default Tenant
            roles_res = await session.execute(
                select(Role).where(Role.tenant_id == tenant.id)
            )
            existing_role_names = {r.name for r in roles_res.scalars().all()}

            # Fetch all permissions for admin binding
            all_perms_res = await session.execute(select(Permission))
            all_permissions = list(all_perms_res.scalars().all())

            # Seed Admin Role
            if "admin" not in existing_role_names:
                admin_role = Role(
                    tenant_id=tenant.id,
                    name="admin",
                    description="Full administrative access to the tenant realm",
                    is_system=True,
                )
                admin_role.permissions = all_permissions
                session.add(admin_role)

            # Seed Member Role
            if "member" not in existing_role_names:
                member_perms = [
                    p for p in all_permissions
                    if p.action in ("read",) or p.resource in ("users",)
                ]
                member_role = Role(
                    tenant_id=tenant.id,
                    name="member",
                    description="Standard organization member with read access",
                    is_system=True,
                )
                member_role.permissions = member_perms
                session.add(member_role)

            # Seed Viewer Role
            if "viewer" not in existing_role_names:
                viewer_perms = [p for p in all_permissions if p.action == "read"]
                viewer_role = Role(
                    tenant_id=tenant.id,
                    name="viewer",
                    description="Read-only observer role",
                    is_system=True,
                )
                viewer_role.permissions = viewer_perms
                session.add(viewer_role)

            await session.commit()
            logger.info("Baseline database fixtures successfully verified")
        except Exception as e:
            await session.rollback()
            logger.error(f"Error seeding database fixtures: {e}")
            raise


async def close_db() -> None:
    """Dispose of engine connection pool."""
    await engine.dispose()
