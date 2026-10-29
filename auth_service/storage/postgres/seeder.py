"""Realistic Database Seeding & Mock Data Generation Subsystem (Layer 4).

Generates sample organizations, administrative and standard users, role assignments,
machine API keys, and simulated audit logs for testing and staging environments.
"""

from datetime import datetime, timezone, timedelta
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession
from auth_service.config import settings
from auth_service.core.logger import logger
from auth_service.core.security.password import hash_password
from auth_service.core.security.api_keys import generate_api_key
from auth_service.models.tenant import Tenant
from auth_service.models.user import User
from auth_service.models.role import Role
from auth_service.models.api_key import APIKey
from auth_service.models.audit_log import AuditLog
from auth_service.storage.postgres.role_repo import RoleRepository
from auth_service.storage.postgres.user_repo import UserRepository


MOCK_TENANTS = [
    {"id": "10000000-0000-0000-0000-000000000001", "name": "Acme Global", "slug": "acme-global", "plan": "enterprise"},
    {"id": "20000000-0000-0000-0000-000000000002", "name": "Globex Systems", "slug": "globex-systems", "plan": "standard"},
    {"id": "30000000-0000-0000-0000-000000000003", "name": "Initech Corp", "slug": "initech-corp", "plan": "starter"},
]

MOCK_USERS = [
    {"email": "carol.admin@acme.com", "name": "Carol Danvers", "tenant_idx": 0, "role": "admin", "verified": True, "super": True},
    {"email": "peter.dev@acme.com", "name": "Peter Parker", "tenant_idx": 0, "role": "member", "verified": True, "super": False},
    {"email": "bruce.ops@globex.com", "name": "Bruce Banner", "tenant_idx": 1, "role": "admin", "verified": True, "super": False},
    {"email": "tony.eng@globex.com", "name": "Tony Stark", "tenant_idx": 1, "role": "member", "verified": True, "super": False},
    {"email": "clark.lead@initech.com", "name": "Clark Kent", "tenant_idx": 2, "role": "admin", "verified": True, "super": False},
]


class DatabaseSeeder:
    """Seeds multi-tenant demo fixtures."""

    @classmethod
    async def seed_demo_data(cls, session: AsyncSession) -> None:
        """Seed demo organizations, roles, users, and credentials."""
        logger.info("Seeding realistic demo fixtures...")
        user_repo = UserRepository(session)
        role_repo = RoleRepository(session)

        # 1. Seed sample tenants
        for t_data in MOCK_TENANTS:
            res = await session.execute(select(Tenant).where(Tenant.id == t_data["id"]))
            if not res.scalar_one_or_none():
                tenant = Tenant(
                    id=t_data["id"],
                    name=t_data["name"],
                    slug=t_data["slug"],
                    plan=t_data["plan"],
                    is_active=True,
                )
                session.add(tenant)
                await session.flush()

                # Seed baseline roles for this tenant
                await role_repo.create(tenant.id, name="admin", description="Full Admin", is_system=True)
                await role_repo.create(tenant.id, name="member", description="Member", is_system=True)
                await role_repo.create(tenant.id, name="viewer", description="Viewer", is_system=True)

        # 2. Seed mock users
        default_pwd_hash = hash_password("DemoPassword2026!#", rounds=10)
        for u_data in MOCK_USERS:
            target_tenant_id = MOCK_TENANTS[u_data["tenant_idx"]]["id"]
            existing = await user_repo.get_by_email(target_tenant_id, u_data["email"])
            if not existing:
                user = await user_repo.create(
                    tenant_id=target_tenant_id,
                    email=u_data["email"],
                    hashed_password=default_pwd_hash,
                    full_name=u_data["name"],
                    is_active=True,
                    is_verified=u_data["verified"],
                    is_superuser=u_data["super"],
                )
                role = await role_repo.get_by_name(target_tenant_id, u_data["role"])
                if role:
                    await user_repo.assign_role(user, role)

        # 3. Seed demo API keys
        for t_data in MOCK_TENANTS:
            key_res = await session.execute(
                select(APIKey).where(APIKey.tenant_id == t_data["id"])
            )
            if not key_res.scalars().all():
                raw_key, prefix, key_hash = generate_api_key(is_live=True)
                key = APIKey(
                    tenant_id=t_data["id"],
                    name=f"{t_data['name']} Production Key",
                    prefix=prefix,
                    key_hash=key_hash,
                    is_active=True,
                    expires_at=datetime.now(timezone.utc) + timedelta(days=90),
                )
                key.scopes = ["read:users", "write:users", "read:audit"]
                session.add(key)

        await session.commit()
        logger.info("Demo fixtures seeding completed successfully.")


seeder = DatabaseSeeder()
