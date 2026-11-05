"""OAuth Social Authentication API Router (Layer 5: API).

Handles third-party federated identity with Google and GitHub, profile hydration,
account linking, and token pair issuance.
"""

from typing import Any, Dict, List
from urllib.parse import urlencode
from fastapi import APIRouter, Depends, Query, Request, status
from fastapi.responses import RedirectResponse
import httpx
from sqlalchemy.ext.asyncio import AsyncSession
from auth_service.config import settings
from auth_service.core.dependencies import (
    get_current_active_user,
    get_db,
    get_tenant_id,
)
from auth_service.core.exceptions import AuthenticationError, ValidationError
from auth_service.core.logger import logger
from auth_service.core.security.jwt_handler import (
    create_access_token,
    create_refresh_token,
)
from auth_service.core.security.rate_limiter import get_client_ip
from auth_service.core.security.token_rotation import hash_token
from auth_service.models.user import User
from auth_service.storage.postgres.audit_log_repo import AuditLogRepository
from auth_service.storage.postgres.oauth_repo import OAuthRepository
from auth_service.storage.postgres.role_repo import RoleRepository
from auth_service.storage.postgres.token_repo import TokenRepository
from auth_service.storage.postgres.user_repo import UserRepository
from auth_service.api.schemas.auth_schemas import TokenResponse, UserSummary
from auth_service.api.schemas.common import MessageResponse


router = APIRouter(prefix="/oauth", tags=["OAuth & Social Sign-In"])


@router.get(
    "/providers",
    response_model=List[Dict[str, Any]],
    summary="List Supported Social Providers",
    description="Returns metadata about available and configured third-party authentication providers.",
)
async def list_providers():
    return [
        {
            "provider": "google",
            "name": "Google",
            "auth_url": "/api/v1/oauth/google",
            "enabled": bool(settings.GOOGLE_CLIENT_ID),
        },
        {
            "provider": "github",
            "name": "GitHub",
            "auth_url": "/api/v1/oauth/github",
            "enabled": bool(settings.GITHUB_CLIENT_ID),
        },
    ]


@router.get(
    "/google",
    summary="Initiate Google OAuth2 Flow",
    description="Constructs and redirects to Google OAuth2 consent screen.",
)
async def google_login(tenant_id: str = Depends(get_tenant_id)):
    params = {
        "client_id": settings.GOOGLE_CLIENT_ID,
        "redirect_uri": settings.GOOGLE_REDIRECT_URI,
        "response_type": "code",
        "scope": "openid email profile",
        "access_type": "offline",
        "state": tenant_id,
        "prompt": "select_account",
    }
    url = f"https://accounts.google.com/o/oauth2/v2/auth?{urlencode(params)}"
    return RedirectResponse(url)


@router.get(
    "/google/callback",
    response_model=TokenResponse,
    summary="Google OAuth2 Callback",
    description="Exchanges authorization code for tokens and issues AaaS session JWTs.",
)
async def google_callback(
    code: str = Query(..., description="Authorization code returned by Google"),
    state: str = Query(None, description="State parameter containing tenant ID"),
    request: Request = None,
    db: AsyncSession = Depends(get_db),
):
    tenant_id = state or settings.DEFAULT_TENANT_ID
    user_repo = UserRepository(db)
    oauth_repo = OAuthRepository(db)
    token_repo = TokenRepository(db)
    audit_repo = AuditLogRepository(db)
    role_repo = RoleRepository(db)

    # 1. Exchange authorization code for Google access token
    token_url = "https://oauth2.googleapis.com/token"
    token_data = {
        "client_id": settings.GOOGLE_CLIENT_ID,
        "client_secret": settings.GOOGLE_CLIENT_SECRET,
        "code": code,
        "grant_type": "authorization_code",
        "redirect_uri": settings.GOOGLE_REDIRECT_URI,
    }

    # Mock provider response in non-prod or mock test configurations
    if settings.GOOGLE_CLIENT_ID.startswith("mock-"):
        profile_email = f"google_test_{code[:6]}@example.com"
        google_user_id = f"g_sub_{code[:10]}"
        profile_name = "Google Test User"
        google_access_token = f"mock_g_access_{code}"
    else:
        async with httpx.AsyncClient(timeout=10.0) as client:
            resp = await client.post(token_url, data=token_data)
            if resp.status_code != 200:
                raise AuthenticationError(f"Google token exchange failed: {resp.text}")
            tokens = resp.json()
            google_access_token = tokens.get("access_token")

            # Fetch User Profile
            userinfo_resp = await client.get(
                "https://www.googleapis.com/oauth2/v3/userinfo",
                headers={"Authorization": f"Bearer {google_access_token}"},
            )
            if userinfo_resp.status_code != 200:
                raise AuthenticationError("Failed to fetch Google user profile")
            profile = userinfo_resp.json()
            profile_email = profile.get("email")
            google_user_id = profile.get("sub")
            profile_name = profile.get("name")

    if not profile_email:
        raise ValidationError("Google profile did not contain a valid email address")

    # 2. Check for existing OAuth link
    linked_account = await oauth_repo.get_by_provider("google", google_user_id)
    if linked_account:
        user = await user_repo.get_by_id(linked_account.user_id, tenant_id=tenant_id)
    else:
        # Check if user with that email already exists
        user = await user_repo.get_by_email(tenant_id, profile_email)
        if not user:
            # Provision new user account automatically verified
            user = await user_repo.create(
                tenant_id=tenant_id,
                email=profile_email,
                full_name=profile_name,
                is_active=True,
                is_verified=True,
            )
            member_role = await role_repo.get_by_name(tenant_id, "member")
            if member_role:
                await user_repo.assign_role(user, member_role)

        # Link Google account
        await oauth_repo.create_or_update(
            user_id=user.id,
            provider="google",
            provider_user_id=google_user_id,
            email=profile_email,
            access_token=google_access_token,
        )

    # 3. Mint JWT access + refresh tokens
    role_names = [r.name for r in user.roles]
    all_perms = {p.name for r in user.roles for p in r.permissions}

    access_token = create_access_token(
        user_id=user.id,
        email=user.email,
        tenant_id=user.tenant_id,
        roles=role_names,
        permissions=list(all_perms),
    )

    refresh_meta = create_refresh_token(user_id=user.id, tenant_id=user.tenant_id)
    token_digest = hash_token(refresh_meta["token"])

    await token_repo.create(
        user_id=user.id,
        tenant_id=user.tenant_id,
        token_hash=token_digest,
        family_id=refresh_meta["family_id"],
        expires_at=refresh_meta["expires_at"],
    )

    await audit_repo.log(
        tenant_id=user.tenant_id,
        event_type="oauth_login",
        user_id=user.id,
        ip_address=get_client_ip(request) if request else None,
        status="success",
        details={"provider": "google", "email": user.email},
    )

    return TokenResponse(
        access_token=access_token,
        refresh_token=refresh_meta["token"],
        token_type="bearer",
        expires_in=settings.ACCESS_TOKEN_EXPIRE_MINUTES * 60,
        user=UserSummary(
            id=user.id,
            email=user.email,
            full_name=user.full_name,
            tenant_id=user.tenant_id,
            roles=role_names,
            is_verified=user.is_verified,
        ),
    )


@router.get(
    "/github",
    summary="Initiate GitHub OAuth2 Flow",
    description="Constructs and redirects to GitHub OAuth authorization screen.",
)
async def github_login(tenant_id: str = Depends(get_tenant_id)):
    params = {
        "client_id": settings.GITHUB_CLIENT_ID,
        "redirect_uri": settings.GITHUB_REDIRECT_URI,
        "scope": "user:email read:user",
        "state": tenant_id,
    }
    url = f"https://github.com/login/oauth/authorize?{urlencode(params)}"
    return RedirectResponse(url)


@router.get(
    "/github/callback",
    response_model=TokenResponse,
    summary="GitHub OAuth2 Callback",
    description="Exchanges GitHub authorization code and mints AaaS session token pair.",
)
async def github_callback(
    code: str = Query(..., description="Authorization code returned by GitHub"),
    state: str = Query(None, description="State parameter containing tenant ID"),
    request: Request = None,
    db: AsyncSession = Depends(get_db),
):
    tenant_id = state or settings.DEFAULT_TENANT_ID
    user_repo = UserRepository(db)
    oauth_repo = OAuthRepository(db)
    token_repo = TokenRepository(db)
    audit_repo = AuditLogRepository(db)
    role_repo = RoleRepository(db)

    if settings.GITHUB_CLIENT_ID.startswith("mock-"):
        profile_email = f"github_test_{code[:6]}@example.com"
        github_user_id = f"gh_id_{code[:10]}"
        profile_name = "GitHub Test User"
        github_access_token = f"mock_gh_token_{code}"
    else:
        async with httpx.AsyncClient(timeout=10.0) as client:
            # Exchange code for GitHub token
            token_resp = await client.post(
                "https://github.com/login/oauth/access_token",
                headers={"Accept": "application/json"},
                data={
                    "client_id": settings.GITHUB_CLIENT_ID,
                    "client_secret": settings.GITHUB_CLIENT_SECRET,
                    "code": code,
                    "redirect_uri": settings.GITHUB_REDIRECT_URI,
                },
            )
            token_json = token_resp.json()
            github_access_token = token_json.get("access_token")
            if not github_access_token:
                raise AuthenticationError(f"GitHub token exchange failed: {token_json}")

            # Fetch profile
            profile_resp = await client.get(
                "https://api.github.com/user",
                headers={
                    "Authorization": f"Bearer {github_access_token}",
                    "Accept": "application/json",
                },
            )
            profile = profile_resp.json()
            github_user_id = str(profile.get("id"))
            profile_name = profile.get("name") or profile.get("login")
            profile_email = profile.get("email")

            # Fallback to emails endpoint if primary email is private
            if not profile_email:
                emails_resp = await client.get(
                    "https://api.github.com/user/emails",
                    headers={"Authorization": f"Bearer {github_access_token}"},
                )
                emails = emails_resp.json()
                for em in emails:
                    if em.get("primary") and em.get("verified"):
                        profile_email = em.get("email")
                        break

    if not profile_email:
        raise ValidationError("Could not resolve verified email from GitHub account")

    linked_account = await oauth_repo.get_by_provider("github", github_user_id)
    if linked_account:
        user = await user_repo.get_by_id(linked_account.user_id, tenant_id=tenant_id)
    else:
        user = await user_repo.get_by_email(tenant_id, profile_email)
        if not user:
            user = await user_repo.create(
                tenant_id=tenant_id,
                email=profile_email,
                full_name=profile_name,
                is_active=True,
                is_verified=True,
            )
            member_role = await role_repo.get_by_name(tenant_id, "member")
            if member_role:
                await user_repo.assign_role(user, member_role)

        await oauth_repo.create_or_update(
            user_id=user.id,
            provider="github",
            provider_user_id=github_user_id,
            email=profile_email,
            access_token=github_access_token,
        )

    role_names = [r.name for r in user.roles]
    all_perms = {p.name for r in user.roles for p in r.permissions}

    access_token = create_access_token(
        user_id=user.id,
        email=user.email,
        tenant_id=user.tenant_id,
        roles=role_names,
        permissions=list(all_perms),
    )

    refresh_meta = create_refresh_token(user_id=user.id, tenant_id=user.tenant_id)
    token_digest = hash_token(refresh_meta["token"])

    await token_repo.create(
        user_id=user.id,
        tenant_id=user.tenant_id,
        token_hash=token_digest,
        family_id=refresh_meta["family_id"],
        expires_at=refresh_meta["expires_at"],
    )

    await audit_repo.log(
        tenant_id=user.tenant_id,
        event_type="oauth_login",
        user_id=user.id,
        ip_address=get_client_ip(request) if request else None,
        status="success",
        details={"provider": "github", "email": user.email},
    )

    return TokenResponse(
        access_token=access_token,
        refresh_token=refresh_meta["token"],
        token_type="bearer",
        expires_in=settings.ACCESS_TOKEN_EXPIRE_MINUTES * 60,
        user=UserSummary(
            id=user.id,
            email=user.email,
            full_name=user.full_name,
            tenant_id=user.tenant_id,
            roles=role_names,
            is_verified=user.is_verified,
        ),
    )


@router.delete(
    "/{provider}",
    response_model=MessageResponse,
    summary="Unlink External Social Provider",
    description="Detaches a linked OAuth identity provider from the current user account.",
)
async def unlink_oauth_provider(
    provider: str,
    current_user: User = Depends(get_current_active_user),
    db: AsyncSession = Depends(get_db),
):
    oauth_repo = OAuthRepository(db)
    await oauth_repo.unlink(current_user.id, provider)
    return MessageResponse(message=f"Successfully unlinked {provider} provider.")

