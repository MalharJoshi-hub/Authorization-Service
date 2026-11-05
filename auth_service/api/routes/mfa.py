"""Multi-Factor Authentication (MFA / TOTP) Router (Layer 5: API).

Handles TOTP enrollment, authenticator app setup, confirmation, recovery code generation,
and verification challenges.
"""

from typing import List, Optional
from fastapi import APIRouter, Depends, status
from pydantic import BaseModel, Field
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession
from auth_service.core.dependencies import get_current_active_user, get_db
from auth_service.core.exceptions import AuthenticationError, ConflictError, ValidationError
from auth_service.models.mfa import UserMFA
from auth_service.models.user import User
from auth_service.services.mfa_service import mfa_service
from auth_service.api.schemas.common import MessageResponse


router = APIRouter(prefix="/mfa", tags=["Multi-Factor Authentication"])


class MFASetupResponse(BaseModel):
    secret: str
    totp_uri: str
    message: str = "Scan the QR code using your authenticator app (Google Authenticator, Authy, 1Password) and verify with a 6-digit code."


class MFAVerifyRequest(BaseModel):
    code: str = Field(..., min_length=6, max_length=6, description="6-digit TOTP code")


class MFABackupCodesResponse(BaseModel):
    backup_codes: List[str]
    message: str = "Store these backup recovery codes in a safe location. Each code can be used exactly once."


class MFAStatusResponse(BaseModel):
    is_enabled: bool
    confirmed_at: Optional[str] = None


@router.get(
    "/status",
    response_model=MFAStatusResponse,
    summary="Get MFA Status",
    description="Inspect whether Multi-Factor Authentication is active for current account.",
)
async def get_mfa_status(
    current_user: User = Depends(get_current_active_user),
    db: AsyncSession = Depends(get_db),
):
    stmt = select(UserMFA).where(UserMFA.user_id == current_user.id)
    res = await db.execute(stmt)
    mfa_profile = res.scalar_one_or_none()

    if not mfa_profile or not mfa_profile.is_enabled:
        return MFAStatusResponse(is_enabled=False)

    return MFAStatusResponse(
        is_enabled=True,
        confirmed_at=mfa_profile.confirmed_at.isoformat() if mfa_profile.confirmed_at else None,
    )


@router.post(
    "/setup",
    response_model=MFASetupResponse,
    summary="Initiate MFA Setup",
    description="Generates a new TOTP secret key and OTP authorization URI.",
)
async def setup_mfa(
    current_user: User = Depends(get_current_active_user),
    db: AsyncSession = Depends(get_db),
):
    stmt = select(UserMFA).where(UserMFA.user_id == current_user.id)
    res = await db.execute(stmt)
    mfa_profile = res.scalar_one_or_none()

    if mfa_profile and mfa_profile.is_enabled:
        raise ConflictError("MFA is already active on this account")

    secret = mfa_service.generate_secret()
    totp_uri = mfa_service.get_totp_uri(secret, current_user.email)

    if not mfa_profile:
        mfa_profile = UserMFA(
            user_id=current_user.id,
            is_enabled=False,
            secret_key=secret,
        )
        db.add(mfa_profile)
    else:
        mfa_profile.secret_key = secret
        mfa_profile.is_enabled = False

    await db.flush()
    return MFASetupResponse(secret=secret, totp_uri=totp_uri)


@router.post(
    "/verify",
    response_model=MFABackupCodesResponse,
    summary="Confirm & Activate MFA",
    description="Verifies the first TOTP code and generates emergency backup recovery codes.",
)
async def verify_and_activate_mfa(
    payload: MFAVerifyRequest,
    current_user: User = Depends(get_current_active_user),
    db: AsyncSession = Depends(get_db),
):
    stmt = select(UserMFA).where(UserMFA.user_id == current_user.id)
    res = await db.execute(stmt)
    mfa_profile = res.scalar_one_or_none()

    if not mfa_profile:
        raise ValidationError("MFA setup has not been initiated. Call /mfa/setup first.")

    is_valid = mfa_service.verify_totp(mfa_profile.secret_key, payload.code)
    if not is_valid:
        raise AuthenticationError("Invalid verification code. Please check your authenticator clock.")

    # Generate 10 emergency backup recovery codes
    raw_codes, hashed_codes = mfa_service.generate_backup_codes(count=10)
    mfa_profile.is_enabled = True
    mfa_profile.backup_codes = hashed_codes
    await db.flush()

    return MFABackupCodesResponse(backup_codes=raw_codes)


@router.post(
    "/disable",
    response_model=MessageResponse,
    summary="Disable MFA",
    description="Disables Multi-Factor Authentication requirement on account.",
)
async def disable_mfa(
    payload: MFAVerifyRequest,
    current_user: User = Depends(get_current_active_user),
    db: AsyncSession = Depends(get_db),
):
    stmt = select(UserMFA).where(UserMFA.user_id == current_user.id)
    res = await db.execute(stmt)
    mfa_profile = res.scalar_one_or_none()

    if not mfa_profile or not mfa_profile.is_enabled:
        return MessageResponse(message="MFA is not enabled.")

    is_valid = mfa_service.verify_totp(mfa_profile.secret_key, payload.code)
    if not is_valid:
        raise AuthenticationError("Invalid TOTP confirmation code")

    mfa_profile.is_enabled = False
    await db.flush()
    return MessageResponse(message="MFA has been successfully disabled.")

