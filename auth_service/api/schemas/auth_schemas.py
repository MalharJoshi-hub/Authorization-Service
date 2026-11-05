"""Authentication Request and Response Schemas (Layer 5: API).

Validates registration, credential login, token rotation, email verification,
and password reset inputs and outputs.
"""

from typing import List, Optional
from pydantic import BaseModel, EmailStr, Field


class UserRegisterRequest(BaseModel):
    """Payload for user self-registration."""

    email: EmailStr = Field(..., description="Unique email address", example="alex.dev@example.com")
    password: str = Field(..., min_length=8, description="Secure password meeting complexity criteria", example="P@ssw0rd2026!#Secure")
    full_name: Optional[str] = Field(None, max_length=255, description="Full display name", example="Alex Mercer")
    tenant_id: Optional[str] = Field(None, description="Optional tenant organization boundary UUID")


class UserRegisterResponse(BaseModel):
    """Response returned upon successful account registration."""

    id: str
    email: str
    full_name: Optional[str] = None
    tenant_id: str
    is_verified: bool
    message: str = "Registration successful. Please verify your email."
    verification_token_preview: Optional[str] = None  # Populated in non-production environments for automated testing


class UserLoginRequest(BaseModel):
    """Payload for password credential authentication."""

    email: EmailStr = Field(..., example="alex.dev@example.com")
    password: str = Field(..., example="P@ssw0rd2026!#Secure")
    tenant_id: Optional[str] = Field(None, description="Optional target tenant boundary")


class UserSummary(BaseModel):
    """Condensed user identity summary included in token responses."""

    id: str
    email: str
    full_name: Optional[str] = None
    tenant_id: str
    roles: List[str]
    is_verified: bool


class TokenResponse(BaseModel):
    """Bearer token pair and identity context returned upon authentication."""

    access_token: str
    refresh_token: str
    token_type: str = "bearer"
    expires_in: int = Field(..., description="Access token lifetime in seconds")
    user: UserSummary


class VerifyEmailRequest(BaseModel):
    """Payload for validating email verification tokens."""

    token: str = Field(..., min_length=16, description="URL-safe cryptographic verification token")


class ResendVerificationRequest(BaseModel):
    """Payload to trigger dispatch of a fresh verification email."""

    email: EmailStr
    tenant_id: Optional[str] = None


class RefreshTokenRequest(BaseModel):
    """Payload for token exchange and rotation."""

    refresh_token: str = Field(..., description="Current long-lived refresh token")


class ForgotPasswordRequest(BaseModel):
    """Payload to request password reset authorization token."""

    email: EmailStr
    tenant_id: Optional[str] = None


class ResetPasswordRequest(BaseModel):
    """Payload to commit password change using authorization token."""

    token: str = Field(..., description="Password reset authorization token")
    new_password: str = Field(..., min_length=8, description="New compliant password")


class LogoutRequest(BaseModel):
    """Payload for terminal session revocation."""

    refresh_token: Optional[str] = Field(None, description="Optional refresh token to invalidate")

