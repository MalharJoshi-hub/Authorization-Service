"""User Repository (Layer 4).

Encapsulates all PostgreSQL data access operations for user identities,
including tenant-scoped queries, pagination, credential updates, and role associations.
"""

from datetime import datetime, timezone
from typing import List, Optional, Tuple
from sqlalchemy import func, select, update, delete
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload
from auth_service.models.user import User
from auth_service.models.role import Role
from auth_service.core.exceptions import ResourceNotFoundError, ConflictError


class UserRepository:
    """Data access repository for User entities."""

    def __init__(self, session: AsyncSession):
        self.session = session

    async def create(
        self,
        tenant_id: Optional[str] = None,
        email: Optional[str] = None,
        hashed_password: Optional[str] = None,
        full_name: Optional[str] = None,
        avatar_url: Optional[str] = None,
        is_active: bool = True,
        is_verified: bool = False,
        is_superuser: bool = False,
        **kwargs,
    ) -> User:
        """Create a new user within a tenant."""
        if email is None and tenant_id and "@" in tenant_id:
            email = tenant_id
            tenant_id = kwargs.get("tenant_id") or "00000000-0000-0000-0000-000000000001"
        tenant_id = tenant_id or kwargs.get("tenant_id") or "00000000-0000-0000-0000-000000000001"
        normalized_email = email.lower().strip()
        # Verify email uniqueness within tenant
        existing = await self.get_by_email(tenant_id, normalized_email)
        if existing:
            raise ConflictError(f"User with email '{normalized_email}' already exists in this tenant")

        user = User(
            tenant_id=tenant_id,
            email=normalized_email,
            hashed_password=hashed_password,
            full_name=full_name,
            avatar_url=avatar_url,
            is_active=is_active,
            is_verified=is_verified,
            is_superuser=is_superuser,
        )
        self.session.add(user)
        await self.session.flush()
        await self.session.refresh(user, ["roles"])
        return user

    async def get_by_id(self, user_id: str, tenant_id: Optional[str] = None) -> Optional[User]:
        """Fetch user by primary key, optionally scoped to tenant."""
        stmt = (
            select(User)
            .options(selectinload(User.roles).selectinload(Role.permissions))
            .where(User.id == user_id)
        )
        if tenant_id:
            stmt = stmt.where(User.tenant_id == tenant_id)
        res = await self.session.execute(stmt)
        return res.scalar_one_or_none()

    async def get_by_email(
        self,
        tenant_id_or_email: Optional[str] = None,
        email: Optional[str] = None,
        tenant_id: Optional[str] = None,
        **kwargs,
    ) -> Optional[User]:
        """Fetch user by normalized email within tenant."""
        target_email = email
        target_tenant = tenant_id

        if tenant_id_or_email:
            if "@" in tenant_id_or_email:
                target_email = tenant_id_or_email
            elif not target_tenant:
                target_tenant = tenant_id_or_email
            elif not target_email:
                target_email = tenant_id_or_email

        if not target_email and "email" in kwargs:
            target_email = kwargs["email"]
        if not target_tenant and "tenant_id" in kwargs:
            target_tenant = kwargs["tenant_id"]

        stmt = select(User).options(selectinload(User.roles).selectinload(Role.permissions))
        if target_email:
            stmt = stmt.where(User.email == target_email.lower().strip())
        if target_tenant:
            stmt = stmt.where(User.tenant_id == str(target_tenant))

        res = await self.session.execute(stmt)
        return res.scalar_one_or_none()

    async def list_users(
        self,
        tenant_id: Optional[str] = None,
        skip: int = 0,
        limit: int = 50,
        search: Optional[str] = None,
        is_active: Optional[bool] = None,
    ) -> Tuple[List[User], int]:
        """Retrieve paginated user list with optional search and filtering."""
        query = select(User).options(selectinload(User.roles).selectinload(Role.permissions))
        count_query = select(func.count(User.id))

        if tenant_id:
            query = query.where(User.tenant_id == tenant_id)
            count_query = count_query.where(User.tenant_id == tenant_id)

        if is_active is not None:
            query = query.where(User.is_active == is_active)
            count_query = count_query.where(User.is_active == is_active)

        if search:
            pattern = f"%{search.strip().lower()}%"
            query = query.where(
                (User.email.ilike(pattern)) | (User.full_name.ilike(pattern))
            )
            count_query = count_query.where(
                (User.email.ilike(pattern)) | (User.full_name.ilike(pattern))
            )

        total_res = await self.session.execute(count_query)
        total = total_res.scalar() or 0

        query = query.order_by(User.created_at.desc()).offset(skip).limit(limit)
        res = await self.session.execute(query)
        users = list(res.scalars().all())

        return users, total

    async def update(
        self,
        user_id: str,
        tenant_id: Optional[str] = None,
        **kwargs,
    ) -> User:
        """Update user record attributes."""
        user = await self.get_by_id(user_id, tenant_id=tenant_id)
        if not user:
            raise ResourceNotFoundError(f"User '{user_id}' not found")

        for key, value in kwargs.items():
            if hasattr(user, key) and value is not None:
                setattr(user, key, value)

        user.updated_at = datetime.now(timezone.utc)
        await self.session.flush()
        return user

    async def update_last_login(self, user_id: str) -> None:
        """Update last login timestamp."""
        await self.session.execute(
            update(User)
            .where(User.id == user_id)
            .values(last_login_at=datetime.now(timezone.utc))
        )
        await self.session.flush()

    async def delete(self, user_id: str, tenant_id: Optional[str] = None, soft_delete: bool = True) -> bool:
        """Delete user account (soft delete or hard delete)."""
        user = await self.get_by_id(user_id, tenant_id=tenant_id)
        if not user:
            raise ResourceNotFoundError(f"User '{user_id}' not found")

        if soft_delete:
            user.is_active = False
            user.updated_at = datetime.now(timezone.utc)
            await self.session.flush()
        else:
            await self.session.delete(user)
            await self.session.flush()
        return True

    async def assign_role(self, user: User, role: Role) -> None:
        """Bind a role to a user."""
        if "roles" not in user.__dict__:
            await self.session.refresh(user, ["roles"])
        if role not in user.roles:
            user.roles.append(role)
            await self.session.flush()

    async def remove_role(self, user: User, role: Role) -> None:
        """Unbind a role from a user."""
        if role in user.roles:
            user.roles.remove(role)
            await self.session.flush()
