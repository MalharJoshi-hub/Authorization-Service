"""Authentication API Router (Layer 5: API).

Implements core authentication lifecycles: registration, verification, credential login,
session token rotation, logout revocation, and password recovery.
"""

from datetime import datetime, timezone, timedelta
from typing import Optional
from pydantic import BaseModel
from fastapi import APIRouter, Depends, Header, HTTPException, Request, Response, status
from sqlalchemy.ext.asyncio import AsyncSession
from auth_service.config import settings
from auth_service.core.dependencies import (
    get_current_active_user,
    get_db,
    get_tenant_id,
    get_token_payload,
)
from auth_service.core.exceptions import (
    AccountLockedError,
    AuthenticationError,
    TokenReuseDetectedError,
    ValidationError,
)
from auth_service.core.logger import logger
from auth_service.core.security.jwt_handler import (
    create_access_token,
    create_refresh_token,
    decode_token,
    get_token_jti,
)
from auth_service.core.security.lockout import lockout_manager
from auth_service.core.security.password import (
    hash_password,
    validate_password_complexity,
    verify_password,
)
from auth_service.core.security.request_validator import validate_request_size
from auth_service.core.security.rate_limiter import check_rate_limit, get_client_ip
from auth_service.core.security.token_blacklist import token_blacklist
from auth_service.core.security.token_rotation import (
    hash_token,
    token_rotation_manager,
)
from auth_service.models.user import User
from auth_service.storage.postgres.audit_log_repo import AuditLogRepository
from auth_service.storage.postgres.role_repo import RoleRepository
from auth_service.storage.postgres.token_repo import TokenRepository
from auth_service.storage.postgres.user_repo import UserRepository
from auth_service.storage.redis.token_store import redis_token_store
from auth_service.api.schemas.auth_schemas import (
    ForgotPasswordRequest,
    LogoutRequest,
    RefreshTokenRequest,
    ResendVerificationRequest,
    ResetPasswordRequest,
    TokenResponse,
    UserLoginRequest,
    UserRegisterRequest,
    UserRegisterResponse,
    UserSummary,
    VerifyEmailRequest,
)
from auth_service.api.schemas.common import MessageResponse


router = APIRouter(prefix="/auth", tags=["Authentication"])


@router.post(
    "/register",
    response_model=UserRegisterResponse,
    status_code=status.HTTP_201_CREATED,
    summary="Register New User Account",
    description="Registers a new user account with mandatory email verification workflow.",
)
async def register(
    payload: UserRegisterRequest,
    request: Request,
    tenant_id: str = Depends(get_tenant_id),
    db: AsyncSession = Depends(get_db),
):
    # Enforce payload size limit
    await validate_request_size(request)

    # Enforce registration rate limiting (3 requests/min per IP)
    await check_rate_limit(
        request, "register", settings.RATE_LIMIT_REGISTER_PER_MINUTE, window_seconds=60
    )

    # Validate password complexity
    is_valid, error_msg = validate_password_complexity(payload.password)
    if not is_valid:
        raise ValidationError(error_msg)

    target_tenant_id = payload.tenant_id or tenant_id
    user_repo = UserRepository(db)
    audit_repo = AuditLogRepository(db)

    # Hash password with bcrypt cost 12
    hashed = hash_password(payload.password)

    user = await user_repo.create(
        tenant_id=target_tenant_id,
        email=payload.email,
        hashed_password=hashed,
        full_name=payload.full_name,
        is_active=True,
        is_verified=False,
    )

    # Assign default member role
    role_repo = RoleRepository(db)
    member_role = await role_repo.get_by_name(target_tenant_id, "member")
    if member_role:
        await user_repo.assign_role(user, member_role)

    # Issue transient email verification token
    verify_token = await redis_token_store.create_email_verification_token(
        user_id=user.id,
        email=user.email,
        tenant_id=target_tenant_id,
    )

    # Record immutable audit event
    await audit_repo.log(
        tenant_id=target_tenant_id,
        event_type="register",
        user_id=user.id,
        ip_address=get_client_ip(request),
        user_agent=request.headers.get("user-agent"),
        status="success",
        details={"email": user.email},
    )

    token_preview = verify_token if not settings.is_production else None

    return UserRegisterResponse(
        id=user.id,
        email=user.email,
        full_name=user.full_name,
        tenant_id=user.tenant_id,
        is_verified=user.is_verified,
        message="Registration successful. Please verify your email.",
        verification_token_preview=token_preview,
    )


@router.post(
    "/verify-email",
    response_model=MessageResponse,
    summary="Verify User Email",
    description="Validates a one-time verification token and marks user account as verified.",
)
async def verify_email(
    payload: VerifyEmailRequest,
    request: Request,
    db: AsyncSession = Depends(get_db),
):
    data = await redis_token_store.verify_and_consume_email_token(payload.token)
    if not data:
        raise ValidationError("Invalid, consumed, or expired verification token", code="INVALID_TOKEN")

    user_repo = UserRepository(db)
    audit_repo = AuditLogRepository(db)

    user = await user_repo.get_by_id(data["user_id"], tenant_id=data.get("tenant_id"))
    if not user:
        raise ValidationError("User account associated with token not found")

    await user_repo.update(user.id, is_verified=True)

    await audit_repo.log(
        tenant_id=user.tenant_id,
        event_type="email_verified",
        user_id=user.id,
        ip_address=get_client_ip(request),
        user_agent=request.headers.get("user-agent"),
        status="success",
    )

    return MessageResponse(message="Email address successfully verified. You may now log in.")


@router.post(
    "/resend-verification",
    response_model=MessageResponse,
    summary="Resend Email Verification Token",
    description="Dispatches a fresh verification token if user account is unverified.",
)
async def resend_verification(
    payload: ResendVerificationRequest,
    request: Request,
    tenant_id: str = Depends(get_tenant_id),
    db: AsyncSession = Depends(get_db),
):
    target_tenant_id = payload.tenant_id or tenant_id
    user_repo = UserRepository(db)
    user = await user_repo.get_by_email(target_tenant_id, payload.email)

    if user and not user.is_verified:
        verify_token = await redis_token_store.create_email_verification_token(
            user_id=user.id,
            email=user.email,
            tenant_id=target_tenant_id,
        )
        preview = verify_token if not settings.is_production else None
        return MessageResponse(
            message="Verification email sent.",
            details={"verification_token_preview": preview} if preview else None,
        )

    # Return identical generic message to avert email enumeration
    return MessageResponse(message="If an unverified account exists, a verification link has been sent.")


@router.post(
    "/login",
    response_model=TokenResponse,
    summary="Authenticate User with Password Credentials",
    description="Validates credentials, evaluates account lockout, and issues an access/refresh token pair.",
)
async def login(
    payload: UserLoginRequest,
    request: Request,
    tenant_id: str = Depends(get_tenant_id),
    db: AsyncSession = Depends(get_db),
):
    # Enforce login brute force rate limiting (5 requests/min per IP)
    await check_rate_limit(
        request, "login", settings.RATE_LIMIT_LOGIN_PER_MINUTE, window_seconds=60
    )

    target_tenant_id = payload.tenant_id or tenant_id
    user_repo = UserRepository(db)
    audit_repo = AuditLogRepository(db)
    token_repo = TokenRepository(db)

    # 1. Check if account identifier is currently locked out
    is_locked, remaining_ttl = await lockout_manager.is_locked(payload.email)
    if is_locked:
        lockout_mins = max(1, remaining_ttl // 60)
        raise AccountLockedError(
            message=f"Account is temporarily locked due to excessive failed attempts. Try again in {lockout_mins} minutes.",
            lockout_minutes=lockout_mins,
        )

    # 2. Fetch user
    user = await user_repo.get_by_email(target_tenant_id, payload.email)

    # 3. Verify password
    valid_password = False
    if user and user.hashed_password:
        valid_password = verify_password(payload.password, user.hashed_password)

    if not user or not valid_password:
        # Record failed attempt towards lockout threshold
        count, now_locked = await lockout_manager.record_failed_attempt(payload.email)
        await audit_repo.log(
            tenant_id=target_tenant_id,
            event_type="login",
            ip_address=get_client_ip(request),
            user_agent=request.headers.get("user-agent"),
            status="failed",
            details={"email": payload.email, "attempt_count": count},
        )
        if now_locked:
            raise AccountLockedError(
                "Excessive failed login attempts. Account has been locked for 15 minutes."
            )
        raise AuthenticationError("Invalid email or password credentials")

    # 4. Check account status
    if not user.is_active:
        raise AuthenticationError("Account is inactive or suspended")

    # 5. Clear failed attempts counter
    await lockout_manager.reset_attempts(user.email)
    await user_repo.update_last_login(user.id)

    # 6. Extract roles and permissions
    role_names = [r.name for r in user.roles]
    all_perms: set[str] = set()
    for r in user.roles:
        for p in r.permissions:
            all_perms.add(p.name)

    # 7. Mint access token
    access_token = create_access_token(
        user_id=user.id,
        email=user.email,
        tenant_id=user.tenant_id,
        roles=role_names,
        permissions=list(all_perms),
    )

    # 8. Mint and persist refresh token
    refresh_meta = create_refresh_token(user_id=user.id, tenant_id=user.tenant_id)
    token_digest = hash_token(refresh_meta["token"])

    await token_repo.create(
        user_id=user.id,
        tenant_id=user.tenant_id,
        token_hash=token_digest,
        family_id=refresh_meta["family_id"],
        expires_at=refresh_meta["expires_at"],
    )

    # 9. Log successful audit entry
    await audit_repo.log(
        tenant_id=user.tenant_id,
        event_type="login",
        user_id=user.id,
        ip_address=get_client_ip(request),
        user_agent=request.headers.get("user-agent"),
        status="success",
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


@router.post(
    "/refresh",
    response_model=TokenResponse,
    summary="Rotate Refresh Token & Mint New Access Token",
    description="Implements single-use refresh token rotation with cryptographic reuse detection.",
)
async def refresh_tokens(
    payload: RefreshTokenRequest,
    request: Request,
    db: AsyncSession = Depends(get_db),
):
    # Decode refresh token
    claims = decode_token(payload.refresh_token, expected_type="refresh")
    user_id = claims.get("sub")
    family_id = claims.get("family_id")
    tenant_id = claims.get("tenant_id")

    token_repo = TokenRepository(db)
    user_repo = UserRepository(db)
    audit_repo = AuditLogRepository(db)

    # Lookup persisted token record by hash
    token_digest = hash_token(payload.refresh_token)
    stored_token = await token_repo.get_by_hash(token_digest)

    # If token was previously revoked or doesn't exist, flag potential theft
    if not stored_token or stored_token.is_revoked:
        if family_id:
            # Terminate all active sessions in token family
            await token_repo.revoke_family(family_id)
            await audit_repo.log(
                tenant_id=tenant_id or settings.DEFAULT_TENANT_ID,
                event_type="token_reuse_attack",
                user_id=user_id,
                ip_address=get_client_ip(request),
                user_agent=request.headers.get("user-agent"),
                status="blocked",
                details={"family_id": family_id},
            )
        raise TokenReuseDetectedError(
            "Refresh token has already been rotated or revoked. Potential theft detected. Session revoked."
        )

    # Revoke current token immediately (single use)
    await token_repo.revoke_token(stored_token.id)

    # Resolve active user
    user = await user_repo.get_by_id(user_id, tenant_id=tenant_id)
    if not user or not user.is_active:
        raise AuthenticationError("User account inactive or removed")

    role_names = [r.name for r in user.roles]
    all_perms: set[str] = set()
    for r in user.roles:
        for p in r.permissions:
            all_perms.add(p.name)

    # Mint new access token
    new_access_token = create_access_token(
        user_id=user.id,
        email=user.email,
        tenant_id=user.tenant_id,
        roles=role_names,
        permissions=list(all_perms),
    )

    # Mint replacement refresh token keeping same family_id
    new_refresh = create_refresh_token(
        user_id=user.id,
        tenant_id=user.tenant_id,
        family_id=family_id,
    )
    new_token_digest = hash_token(new_refresh["token"])

    await token_repo.create(
        user_id=user.id,
        tenant_id=user.tenant_id,
        token_hash=new_token_digest,
        family_id=family_id,
        expires_at=new_refresh["expires_at"],
    )

    await audit_repo.log(
        tenant_id=user.tenant_id,
        event_type="token_refresh",
        user_id=user.id,
        ip_address=get_client_ip(request),
        user_agent=request.headers.get("user-agent"),
        status="success",
    )

    return TokenResponse(
        access_token=new_access_token,
        refresh_token=new_refresh["token"],
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


@router.post(
    "/logout",
    response_model=MessageResponse,
    summary="Revoke Active Session & Blacklist Access Token",
    description="Revokes the current access token in Redis blacklist and invalidates the refresh token.",
)
async def logout(
    payload: Optional[LogoutRequest] = None,
    request: Request = None,
    auth_header: Optional[str] = Header(None, alias="Authorization"),
    db: AsyncSession = Depends(get_db),
):
    token_repo = TokenRepository(db)
    audit_repo = AuditLogRepository(db)
    user_id = None
    tenant_id = settings.DEFAULT_TENANT_ID

    # 1. Blacklist access token JTI if present
    if auth_header and auth_header.startswith("Bearer "):
        raw_token = auth_header.replace("Bearer ", "").strip()
        try:
            claims = decode_token(raw_token, expected_type="access")
            jti = claims.get("jti")
            exp = claims.get("exp", 0)
            user_id = claims.get("sub")
            tenant_id = claims.get("tenant_id", tenant_id)

            now = int(datetime.now(timezone.utc).timestamp())
            ttl = max(1, exp - now)
            if jti:
                await token_blacklist.blacklist_token(jti, ttl)
        except Exception:
            pass

    # 2. Revoke submitted refresh token
    if payload and payload.refresh_token:
        try:
            digest = hash_token(payload.refresh_token)
            stored = await token_repo.get_by_hash(digest)
            if stored:
                await token_repo.revoke_token(stored.id)
                user_id = stored.user_id
                tenant_id = stored.tenant_id
        except Exception:
            pass

    if user_id:
        await audit_repo.log(
            tenant_id=tenant_id,
            event_type="logout",
            user_id=user_id,
            ip_address=get_client_ip(request),
            user_agent=request.headers.get("user-agent") if request else None,
            status="success",
        )

    return MessageResponse(message="Successfully logged out and session revoked.")


@router.post(
    "/forgot-password",
    response_model=MessageResponse,
    summary="Request Password Reset Link",
    description="Generates a one-time password recovery authorization token.",
)
async def forgot_password(
    payload: ForgotPasswordRequest,
    request: Request,
    tenant_id: str = Depends(get_tenant_id),
    db: AsyncSession = Depends(get_db),
):
    target_tenant_id = payload.tenant_id or tenant_id
    user_repo = UserRepository(db)
    audit_repo = AuditLogRepository(db)

    user = await user_repo.get_by_email(target_tenant_id, payload.email)
    preview = None

    if user:
        reset_token = await redis_token_store.create_password_reset_token(
            user_id=user.id,
            email=user.email,
            tenant_id=target_tenant_id,
        )
        if not settings.is_production:
            preview = reset_token

        await audit_repo.log(
            tenant_id=target_tenant_id,
            event_type="password_reset_requested",
            user_id=user.id,
            ip_address=get_client_ip(request),
            user_agent=request.headers.get("user-agent"),
            status="success",
        )

    return MessageResponse(
        message="If an account matches that email address, password reset instructions have been dispatched.",
        details={"reset_token_preview": preview} if preview else None,
    )


@router.post(
    "/reset-password",
    response_model=MessageResponse,
    summary="Confirm Password Reset",
    description="Consumes reset token, validates complexity, updates password, and terminates all active sessions.",
)
async def reset_password(
    payload: ResetPasswordRequest,
    request: Request,
    db: AsyncSession = Depends(get_db),
):
    # Validate password complexity
    is_valid, error_msg = validate_password_complexity(payload.new_password)
    if not is_valid:
        raise ValidationError(error_msg)

    # Consume token
    data = await redis_token_store.consume_password_reset_token(payload.token)
    if not data:
        raise ValidationError("Invalid, consumed, or expired password reset token", code="INVALID_TOKEN")

    user_repo = UserRepository(db)
    token_repo = TokenRepository(db)
    audit_repo = AuditLogRepository(db)

    user_id = data["user_id"]
    tenant_id = data.get("tenant_id")

    user = await user_repo.get_by_id(user_id, tenant_id=tenant_id)
    if not user:
        raise ResourceNotFoundError("Associated user account not found")

    # Hash new password
    new_hashed = hash_password(payload.new_password)
    await user_repo.update(user.id, hashed_password=new_hashed)

    # Invalidate all existing refresh tokens for security
    await token_repo.revoke_user_sessions(user.id)

    # Unlock account if previously locked
    await lockout_manager.unlock_account(user.email)

    await audit_repo.log(
        tenant_id=user.tenant_id,
        event_type="password_reset_completed",
        user_id=user.id,
        ip_address=get_client_ip(request),
        user_agent=request.headers.get("user-agent"),
        status="success",
    )

    return MessageResponse(
        message="Password has been successfully updated. All previous sessions have been invalidated."
    )


class AuthIntrospectBody(BaseModel):
    token: str
    token_type_hint: Optional[str] = None


@router.post(
    "/introspect",
    summary="Token Introspection Endpoint",
)
async def auth_token_introspect(
    payload: AuthIntrospectBody,
    db: AsyncSession = Depends(get_db),
):
    from auth_service.services.token_introspection_service import token_introspection_service
    return await token_introspection_service.introspect(
        db=db,
        token=payload.token,
        token_type_hint=payload.token_type_hint,
    )

