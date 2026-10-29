"""Admin Dashboard & Observability Schemas (Layer 5: API).

Validates user administrative management, compliance audit querying, and telemetry metrics.
"""

from datetime import datetime
from typing import Any, Dict, List, Optional
from pydantic import BaseModel, Field


class AdminUserUpdateRequest(BaseModel):
    """Payload for administrator mutation of user account state."""

    full_name: Optional[str] = None
    is_active: Optional[bool] = None
    is_verified: Optional[bool] = None
    is_superuser: Optional[bool] = None
    role_names: Optional[List[str]] = Field(None, description="Explicit list of role names to bind")


class AuditLogResponse(BaseModel):
    """Immutable audit trail log entry representation."""

    id: str
    tenant_id: str
    user_id: Optional[str] = None
    event_type: str
    ip_address: Optional[str] = None
    user_agent: Optional[str] = None
    status: str
    details: Dict[str, Any] = Field(default_factory=dict)
    created_at: datetime

    class Config:
        from_attributes = True


class AnalyticsOverviewResponse(BaseModel):
    """Aggregated platform security and authentication metrics."""

    period_days: int
    total_events: int
    successful_logins: int
    failed_logins: int
    new_registrations: int
    password_resets: int


class AnalyticsEventCount(BaseModel):
    """Event frequency breakdown per event category."""

    event_type: str
    count: int
