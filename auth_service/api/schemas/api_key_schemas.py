"""API Key Management Schemas (Layer 5: API).

Validates machine credential provisioning, scope constraints, and response representations.
"""

from datetime import datetime
from typing import List, Optional
from pydantic import BaseModel, Field


class APIKeyCreateRequest(BaseModel):
    """Payload to mint a new machine API key."""

    name: str = Field(..., min_length=2, max_length=100, example="CI/CD Integration Key")
    scopes: List[str] = Field(default_factory=list, example=["read:users", "manage:api_keys"])
    expires_in_days: Optional[int] = Field(None, ge=1, le=365, description="Optional validity duration in days")


class APIKeyCreatedResponse(BaseModel):
    """Returned ONLY ONCE upon creation with the raw secret token."""

    id: str
    name: str
    prefix: str
    raw_key: str = Field(..., description="High-entropy raw API key. Shown ONCE; store securely!")
    scopes: List[str]
    expires_at: Optional[datetime] = None
    created_at: datetime
    message: str = "API Key successfully generated. The raw_key will never be displayed again."


class APIKeyResponse(BaseModel):
    """Safe metadata representation of an API key (raw secret omitted)."""

    id: str
    tenant_id: str
    name: str
    prefix: str
    masked_key: str
    scopes: List[str]
    is_active: bool
    last_used_at: Optional[datetime] = None
    expires_at: Optional[datetime] = None
    created_at: datetime

    class Config:
        from_attributes = True

