"""OAuth Account Repository (Layer 4).

Persists and resolves third-party social provider bindings (Google, GitHub).
"""

from typing import Any, Dict, List, Optional
from sqlalchemy import select, delete
from sqlalchemy.ext.asyncio import AsyncSession
from auth_service.models.oauth_account import OAuthAccount
from auth_service.core.exceptions import ResourceNotFoundError


class OAuthRepository:
    """Data access repository for OAuthAccount entities."""

    def __init__(self, session: AsyncSession):
        self.session = session

    async def get_by_provider(self, provider: str, provider_user_id: str) -> Optional[OAuthAccount]:
        """Lookup linked account by provider and external account ID."""
        stmt = select(OAuthAccount).where(
            OAuthAccount.provider == provider.lower(),
            OAuthAccount.provider_user_id == str(provider_user_id),
        )
        res = await self.session.execute(stmt)
        return res.scalar_one_or_none()

    async def create_or_update(
        self,
        user_id: str,
        provider: str,
        provider_user_id: str,
        email: Optional[str] = None,
        access_token: Optional[str] = None,
        refresh_token: Optional[str] = None,
        profile_data: Optional[Dict[str, Any]] = None,
    ) -> OAuthAccount:
        """Bind social identity to an existing or newly provisioned user."""
        account = await self.get_by_provider(provider, provider_user_id)
        if not account:
            account = OAuthAccount(
                user_id=user_id,
                provider=provider.lower(),
                provider_user_id=str(provider_user_id),
                email=email,
                access_token=access_token,
                refresh_token=refresh_token,
            )
            if profile_data:
                account.profile_data = profile_data
            self.session.add(account)
        else:
            account.user_id = user_id
            account.email = email or account.email
            if access_token:
                account.access_token = access_token
            if refresh_token:
                account.refresh_token = refresh_token
            if profile_data:
                account.profile_data = profile_data

        await self.session.flush()
        return account

    async def get_user_accounts(self, user_id: str) -> List[OAuthAccount]:
        """Retrieve all external accounts linked to a user."""
        res = await self.session.execute(
            select(OAuthAccount).where(OAuthAccount.user_id == user_id)
        )
        return list(res.scalars().all())

    async def unlink(self, user_id: str, provider: str) -> bool:
        """Unlink an external identity provider from a user account."""
        res = await self.session.execute(
            delete(OAuthAccount).where(
                OAuthAccount.user_id == user_id,
                OAuthAccount.provider == provider.lower(),
            )
        )
        await self.session.flush()
        if res.rowcount == 0:
            raise ResourceNotFoundError(f"OAuth provider '{provider}' not linked to user")
        return True
