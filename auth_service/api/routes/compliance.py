"""GDPR and CCPA Data Governance and Compliance Routes."""

from __future__ import annotations

from typing import Any, Dict

from fastapi import APIRouter, Depends
from sqlalchemy.ext.asyncio import AsyncSession

from auth_service.core.dependencies import get_current_user, get_db
from auth_service.models.user import User
from auth_service.services.compliance_service import ComplianceService

router = APIRouter(prefix="/compliance", tags=["Compliance & Privacy"])


@router.get("/export", response_model=Dict[str, Any])
async def export_my_data(
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
) -> Dict[str, Any]:
    """Export all personal data, audit events, and sessions associated with current user."""
    service = ComplianceService(db)
    return await service.export_user_data(current_user)


@router.post("/forget-me", response_model=Dict[str, Any])
async def erase_my_account(
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
) -> Dict[str, Any]:
    """Execute GDPR Right to be Forgotten request, pseudonymizing all user data."""
    service = ComplianceService(db)
    return await service.erase_user_data(current_user, reason="User self-service GDPR erasure")
