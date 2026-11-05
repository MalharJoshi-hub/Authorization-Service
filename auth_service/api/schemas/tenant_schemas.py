"""Tenant Organization Schemas (Layer 5: API).

Validates tenant provisioning, profile modifications, and member invitation payloads.
"""

from datetime import datetime
from typing import Any, Dict, Optional
from pydantic import BaseModel, EmailStr, Field


class TenantCreateRequest(BaseModel):
    """Payload to provision a new tenant realm."""

    name: str = Field(..., min_length=2, max_length=255, example="Acme Corporation")
    slug: str = Field(..., min_length=2, max_length=100, example="acme")
    plan: Optional[str] = Field("standard", example="enterprise")


class TenantUpdateRequest(BaseModel):
    """Payload to modify tenant metadata."""

    name: Optional[str] = Field(None, min_length=2, max_length=255)
    plan: Optional[str] = None
    is_active: Optional[bool] = None
    settings: Optional[Dict[str, Any]] = None


class TenantResponse(BaseModel):
    """Full tenant organization metadata representation."""

    id: str
    name: str
    slug: str
    plan: str
    is_active: bool
    created_at: datetime

    class Config:
        from_attributes = True


class TenantInviteRequest(BaseModel):
    """Payload to invite a new user into the tenant organization."""

    email: EmailStr = Field(..., example="partner@acme.com")
    role_name: str = Field("member", example="editor")

