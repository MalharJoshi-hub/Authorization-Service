"""Role and Permission Schemas (Layer 5: API).

Validates RBAC role definitions, permission assignments, and policy mappings.
"""

from datetime import datetime
from typing import List, Optional
from pydantic import BaseModel, Field


class PermissionResponse(BaseModel):
    """Granular permission grant item."""

    id: str
    name: str
    resource: str
    action: str
    description: Optional[str] = None
    created_at: Optional[datetime] = None

    class Config:
        from_attributes = True


class PermissionCreateRequest(BaseModel):
    """Payload to register a new permission."""

    name: str = Field(..., example="reports:export", description="Canonical permission name (resource:action)")
    resource: str = Field(..., example="reports", description="Resource noun")
    action: str = Field(..., example="export", description="Operation verb")
    description: Optional[str] = Field(None, description="Detailed explanatory text")


class RoleResponse(BaseModel):
    """Role definition including bound permission grants."""

    id: str
    tenant_id: str
    name: str
    description: Optional[str] = None
    is_system: bool
    permissions: List[PermissionResponse] = Field(default_factory=list)
    created_at: datetime

    class Config:
        from_attributes = True


class RoleCreateRequest(BaseModel):
    """Payload for provisioning a custom role."""

    name: str = Field(..., min_length=2, max_length=50, example="auditor")
    description: Optional[str] = Field(None, example="Compliance auditor with read-only audit log access")
    permission_names: List[str] = Field(default_factory=list, example=["audit:read", "audit:export"])


class RoleUpdateRequest(BaseModel):
    """Payload for updating role metadata."""

    name: Optional[str] = Field(None, min_length=2, max_length=50)
    description: Optional[str] = None


class AssignPermissionsRequest(BaseModel):
    """Payload for binding a list of permissions to a role."""

    permission_names: List[str] = Field(..., min_items=1, example=["users:read", "users:update"])

