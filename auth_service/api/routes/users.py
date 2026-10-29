"""User Profile Management API Router (Layer 5: API).

Provides authenticated endpoints for profile inspection, attribute modification,
password change workflows, and self-service account deactivation.
"""

from fastapi import APIRouter, Depends, Request, status
from sqlalchemy.ext.asyncio import AsyncSession
from auth_service.core.dependencies import (
    get_current_active_user,
    get_db,
    get_tenant_id,
    require_permission,
)
from auth_service.core.exceptions import (
    AuthenticationError,
    ResourceNotFoundError,
    ValidationError,
)
from auth_service.core.security.password import (
    hash_password,
    validate_password_complexity,
    verify_password,
)
from auth_service.core.security.rate_limiter import get_client_ip
from auth_service.models.user import User
from auth_service.storage.postgres.audit_log_repo import AuditLogRepository
from auth_service.storage.postgres.token_repo import TokenRepository
from auth_service.storage.postgres.user_repo import UserRepository
from auth_service.api.schemas.common import MessageResponse
from auth_service.api.schemas.user_schemas import (
    ChangePasswordRequest,
    RoleSummary,
    UserResponse,
    UserUpdateRequest,
)


router = APIRouter(prefix="/users", tags=["User Profiles"])


@router.get(
    "/me",
    response_model=UserResponse,
    summary="Get Current User Profile",
    description="Returns detailed profile data and assigned roles for the currently authenticated identity.",
)
async def get_my_profile(current_user: User = Depends(get_current_active_user)):
    roles_summary = [
        RoleSummary(id=r.id, name=r.name, description=r.description)
        for r in current_user.roles
    ]
    return UserResponse(
        id=current_user.id,
        email=current_user.email,
        full_name=current_user.full_name,
        avatar_url=current_user.avatar_url,
        is_active=current_user.is_active,
        is_verified=current_user.is_verified,
        is_superuser=current_user.is_superuser,
        tenant_id=current_user.tenant_id,
        roles=roles_summary,
        created_at=current_user.created_at,
        last_login_at=current_user.last_login_at,
    )


@router.put(
    "/me",
    response_model=UserResponse,
    summary="Update Current User Profile",
    description="Updates editable profile attributes such as display name and avatar URL.",
)
async def update_my_profile(
    payload: UserUpdateRequest,
    current_user: User = Depends(get_current_active_user),
    db: AsyncSession = Depends(get_db),
):
    user_repo = UserRepository(db)
    updated = await user_repo.update(
        user_id=current_user.id,
        full_name=payload.full_name,
        avatar_url=payload.avatar_url,
    )
    roles_summary = [
        RoleSummary(id=r.id, name=r.name, description=r.description)
        for r in updated.roles
    ]
    return UserResponse(
        id=updated.id,
        email=updated.email,
        full_name=updated.full_name,
        avatar_url=updated.avatar_url,
        is_active=updated.is_active,
        is_verified=updated.is_verified,
        is_superuser=updated.is_superuser,
        tenant_id=updated.tenant_id,
        roles=roles_summary,
        created_at=updated.created_at,
        last_login_at=updated.last_login_at,
    )


@router.put(
    "/me/password",
    response_model=MessageResponse,
    summary="Change Account Password",
    description="Verifies the current password, enforces complexity on the new password, and revokes all other sessions.",
)
async def change_password(
    payload: ChangePasswordRequest,
    request: Request,
    current_user: User = Depends(get_current_active_user),
    db: AsyncSession = Depends(get_db),
):
    # Verify current password
    if not current_user.hashed_password or not verify_password(payload.current_password, current_user.hashed_password):
        raise AuthenticationError("Current password verification failed", code="INVALID_CREDENTIALS")

    # Validate new password complexity
    is_valid, error_msg = validate_password_complexity(payload.new_password)
    if not is_valid:
        raise ValidationError(error_msg)

    user_repo = UserRepository(db)
    token_repo = TokenRepository(db)
    audit_repo = AuditLogRepository(db)

    # Hash and save
    new_hashed = hash_password(payload.new_password)
    await user_repo.update(current_user.id, hashed_password=new_hashed)

    # Revoke all other refresh token sessions
    await token_repo.revoke_user_sessions(current_user.id)

    await audit_repo.log(
        tenant_id=current_user.tenant_id,
        event_type="password_changed",
        user_id=current_user.id,
        ip_address=get_client_ip(request),
        user_agent=request.headers.get("user-agent"),
        status="success",
    )

    return MessageResponse(
        message="Password successfully updated. All other active sessions have been invalidated."
    )


@router.delete(
    "/me",
    response_model=MessageResponse,
    summary="Deactivate Own Account",
    description="Performs soft-deletion of the authenticated account and terminates active sessions.",
)
async def delete_my_account(
    request: Request,
    current_user: User = Depends(get_current_active_user),
    db: AsyncSession = Depends(get_db),
):
    user_repo = UserRepository(db)
    token_repo = TokenRepository(db)
    audit_repo = AuditLogRepository(db)

    await user_repo.delete(current_user.id, soft_delete=True)
    await token_repo.revoke_user_sessions(current_user.id)

    await audit_repo.log(
        tenant_id=current_user.tenant_id,
        event_type="account_deactivated",
        user_id=current_user.id,
        ip_address=get_client_ip(request),
        user_agent=request.headers.get("user-agent"),
        status="success",
    )

    return MessageResponse(message="Account successfully deactivated.")


@router.get(
    "/{user_id}",
    response_model=UserResponse,
    summary="Get User By ID",
    description="Inspects user profile by UUID within tenant boundary. Requires 'users:read' permission.",
)
async def get_user_by_id(
    user_id: str,
    tenant_id: str = Depends(get_tenant_id),
    current_user: User = Depends(require_permission("users:read")),
    db: AsyncSession = Depends(get_db),
):
    user_repo = UserRepository(db)
    user = await user_repo.get_by_id(user_id, tenant_id=tenant_id)
    if not user:
        raise ResourceNotFoundError(f"User '{user_id}' not found")

    roles_summary = [
        RoleSummary(id=r.id, name=r.name, description=r.description)
        for r in user.roles
    ]
    return UserResponse(
        id=user.id,
        email=user.email,
        full_name=user.full_name,
        avatar_url=user.avatar_url,
        is_active=user.is_active,
        is_verified=user.is_verified,
        is_superuser=user.is_superuser,
        tenant_id=user.tenant_id,
        roles=roles_summary,
        created_at=user.created_at,
        last_login_at=user.last_login_at,
    )
