"""User Entity API Schemas (Layer 5: API).

Validates user profile representations, profile modifications, and credential updates.
"""

from datetime import datetime
from typing import List, Optional
from pydantic import BaseModel, EmailStr, Field


class RoleSummary(BaseModel):
    """Compact role representation attached to user responses."""

    id: str
    name: str
    description: Optional[str] = None


class UserResponse(BaseModel):
    """Full user profile representation."""

    id: str
    email: EmailStr
    full_name: Optional[str] = None
    avatar_url: Optional[str] = None
    is_active: bool
    is_verified: bool
    is_superuser: bool
    tenant_id: str
    roles: List[RoleSummary] = Field(default_factory=list)
    created_at: datetime
    last_login_at: Optional[datetime] = None

    class Config:
        from_attributes = True


class UserUpdateRequest(BaseModel):
    """Payload for updating user profile fields."""

    full_name: Optional[str] = Field(None, max_length=255)
    avatar_url: Optional[str] = Field(None, max_length=1024)


class ChangePasswordRequest(BaseModel):
    """Payload for authenticated password rotation."""

    current_password: str = Field(..., description="Current plaintext password")
    new_password: str = Field(..., min_length=8, description="New compliant password")


PasswordChangeRequest = ChangePasswordRequest

