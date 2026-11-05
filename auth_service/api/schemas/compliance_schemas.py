"""Schemas for GDPR/CCPA Compliance and Data Privacy Endpoints."""

from __future__ import annotations

from typing import Any, Dict, List, Optional
from pydantic import BaseModel, Field


class UserExportProfile(BaseModel):
    """User profile data in compliance export."""
    id: str
    email: str
    username: str
    full_name: Optional[str] = None
    tenant_id: Optional[str] = None
    is_active: bool
    is_verified: bool
    mfa_enabled: bool
    created_at: Optional[str] = None
    last_login_at: Optional[str] = None


class UserExportSession(BaseModel):
    """Session record in compliance export."""
    session_id: str
    ip_address: Optional[str] = None
    user_agent: Optional[str] = None
    device_name: Optional[str] = None
    created_at: Optional[str] = None
    expires_at: Optional[str] = None
    is_active: bool


class UserExportAuditEvent(BaseModel):
    """Audit log item in compliance export."""
    event_id: str
    action: str
    resource: str
    ip_address: Optional[str] = None
    status_code: Optional[int] = None
    timestamp: Optional[str] = None


class ComplianceExportMetadata(BaseModel):
    """Metadata block for export payload."""
    export_generated_at: str
    compliance_frameworks: List[str]
    subject_id: str
    sha256_checksum: Optional[str] = None


class ComplianceExportResponse(BaseModel):
    """Full data portability export response bundle."""
    metadata: ComplianceExportMetadata
    profile: UserExportProfile
    roles: List[str]
    sessions: List[UserExportSession]
    recent_audit_events: List[UserExportAuditEvent]


class ForgetMeResponse(BaseModel):
    """Response returned upon completion of GDPR Right to be Forgotten."""
    status: str = Field(..., example="success")
    message: str = Field(..., example="User data pseudonymized")
    pseudonymized_id: str
    erased_at: str

