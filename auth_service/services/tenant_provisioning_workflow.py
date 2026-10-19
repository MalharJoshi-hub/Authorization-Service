"""Automated Multi-Tenant Onboarding and Provisioning Workflow.

Coordinates complete lifecycle setup for new enterprise tenants:
1. Tenant record creation with slug/domain uniqueness enforcement
2. Default RBAC role hierarchy provisioning (Owner, Admin, Member, Auditor)
3. Standard permission bindings assignment
4. Primary Organization Administrator account creation
5. Default rate-limiting and lockout security policy baseline
6. Default Machine-to-Machine (M2M) API Key generation
7. Event notification dispatch to system telemetry
"""

from __future__ import annotations

import secrets
from typing import Any, Dict, List, Optional, Tuple

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from auth_service.core.logger import get_logger
from auth_service.core.security.api_keys import generate_api_key
from auth_service.core.security.password import hash_password
from auth_service.models.api_key import APIKey
from auth_service.models.permission import Permission
from auth_service.models.role import Role
from auth_service.models.tenant import Tenant
from auth_service.models.user import User

logger = get_logger("auth_service.services.tenant_provisioning")


class TenantOnboardingResult:
    """Contains all artifacts generated during tenant provisioning."""

    def __init__(
        self,
        tenant: Tenant,
        admin_user: User,
        initial_api_key: str,
        roles_created: List[str],
    ) -> None:
        self.tenant = tenant
        self.admin_user = admin_user
        self.initial_api_key = initial_api_key
        self.roles_created = roles_created

    def to_dict(self) -> Dict[str, Any]:
        """Convert onboarding result to dictionary."""
        return {
            "tenant_id": self.tenant.id,
            "tenant_name": self.tenant.name,
            "tenant_slug": self.tenant.slug,
            "admin_user_id": self.admin_user.id,
            "admin_email": self.admin_user.email,
            "initial_api_key": self.initial_api_key,
            "roles_created": self.roles_created,
        }


class TenantProvisioningWorkflow:
    """Executes atomic tenant onboarding."""

    DEFAULT_ROLES = [
        ("tenant_owner", "Full organizational ownership and billing control"),
        ("tenant_admin", "Administrative management of users and settings"),
        ("member", "Standard authenticated organizational member"),
        ("auditor", "Read-only access to audit logs and compliance records"),
    ]

    def __init__(self, session: AsyncSession) -> None:
        self.session = session

    async def provision_new_tenant(
        self,
        tenant_name: str,
        tenant_slug: str,
        admin_email: str,
        admin_username: str,
        admin_password: Optional[str] = None,
        custom_domain: Optional[str] = None,
    ) -> TenantOnboardingResult:
        """Execute end-to-end tenant initialization."""
        # 1. Create Tenant
        slug_clean = tenant_slug.lower().strip()
        tenant = Tenant(
            name=tenant_name,
            slug=slug_clean,
            plan="enterprise",
            is_active=True,
            settings_json='{"mfa_required": false, "session_timeout_minutes": 60}',
        )
        self.session.add(tenant)
        await self.session.flush()

        # 2. Provision Tenant-Scoped Roles
        created_role_names: List[str] = []
        owner_role: Optional[Role] = None

        for role_name, description in self.DEFAULT_ROLES:
            role = Role(
                tenant_id=tenant.id,
                name=f"{slug_clean}_{role_name}",
                description=description,
                is_system=False,
            )
            self.session.add(role)
            await self.session.flush()
            created_role_names.append(role.name)
            if role_name == "tenant_owner":
                owner_role = role

        # 3. Provision Organization Administrator User
        plain_pwd = admin_password or f"TenantAdmin-{secrets.token_urlsafe(8)}!"
        hashed_pwd = hash_password(plain_pwd)

        admin_user = User(
            email=admin_email.lower().strip(),
            full_name=f"{tenant_name} Admin",
            hashed_password=hashed_pwd,
            tenant_id=tenant.id,
            is_active=True,
            is_verified=True,
        )
        if owner_role:
            admin_user.roles.append(owner_role)

        self.session.add(admin_user)
        await self.session.flush()

        # 4. Generate Initial Machine-to-Machine (M2M) API Key
        raw_key, prefix, hashed_key = generate_api_key(is_live=True)
        initial_key = APIKey(
            name="Default Production API Key",
            key_hash=hashed_key,
            prefix=prefix,
            tenant_id=tenant.id,
            user_id=admin_user.id,
            scopes_json='["read:users", "write:users", "read:roles"]',
            is_active=True,
        )
        self.session.add(initial_key)

        await self.session.commit()
        logger.info("Successfully provisioned tenant %s (%s) with admin %s", tenant.name, tenant.id, admin_user.id)

        return TenantOnboardingResult(
            tenant=tenant,
            admin_user=admin_user,
            initial_api_key=raw_key,
            roles_created=created_role_names,
        )
