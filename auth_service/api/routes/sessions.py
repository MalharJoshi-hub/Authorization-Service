"""Active User Sessions API Router (Layer 5: API).

Enables users to inspect active device logins, geographical IP addresses,
and remotely terminate compromised or obsolete sessions.
"""

from datetime import datetime
from typing import List, Optional
from fastapi import APIRouter, Depends, Header, Request, status
from pydantic import BaseModel
from sqlalchemy.ext.asyncio import AsyncSession
from auth_service.core.dependencies import get_current_active_user, get_db
from auth_service.models.user import User
from auth_service.services.session_service import session_service
from auth_service.api.schemas.common import MessageResponse


router = APIRouter(prefix="/sessions", tags=["Session & Device Management"])


class SessionResponse(BaseModel):
    id: str
    device_name: str
    ip_address: Optional[str] = None
    user_agent: Optional[str] = None
    is_active: bool
    last_seen_at: datetime
    created_at: datetime


@router.get(
    "",
    response_model=List[SessionResponse],
    summary="List Active Device Sessions",
    description="Inspect all active authenticated client sessions for the current identity.",
)
async def list_sessions(
    current_user: User = Depends(get_current_active_user),
    db: AsyncSession = Depends(get_db),
):
    sessions = await session_service.list_active_sessions(db, current_user.id)
    return [
        SessionResponse(
            id=s.id,
            device_name=s.device_name,
            ip_address=s.ip_address,
            user_agent=s.user_agent,
            is_active=s.is_active,
            last_seen_at=s.last_seen_at,
            created_at=s.created_at,
        )
        for s in sessions
    ]


@router.delete(
    "/{session_id}",
    response_model=MessageResponse,
    summary="Revoke Specific Device Session",
    description="Remotely invalidates a specific active session.",
)
async def revoke_session(
    session_id: str,
    current_user: User = Depends(get_current_active_user),
    db: AsyncSession = Depends(get_db),
):
    await session_service.terminate_session(db, session_id, current_user.id)
    return MessageResponse(message=f"Session '{session_id}' successfully terminated.")


@router.delete(
    "",
    response_model=MessageResponse,
    summary="Revoke All Other Sessions",
    description="Terminates all sessions across all devices belonging to user.",
)
async def revoke_all_sessions(
    current_user: User = Depends(get_current_active_user),
    db: AsyncSession = Depends(get_db),
):
    count = await session_service.terminate_all_except(db, current_user.id)
    return MessageResponse(message=f"Successfully terminated {count} active device sessions.")
