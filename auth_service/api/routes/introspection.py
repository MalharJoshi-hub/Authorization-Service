"""OAuth 2.0 Token Introspection & Revocation Router (Layer 5: API).

Implements RFC 7662 (Token Introspection) and RFC 7009 (Token Revocation).
"""

from typing import Any, Dict, Optional
from fastapi import APIRouter, Depends, Form
from pydantic import BaseModel, Field
from sqlalchemy.ext.asyncio import AsyncSession
from auth_service.core.dependencies import get_db
from auth_service.services.token_introspection_service import token_introspection_service
from auth_service.api.schemas.common import MessageResponse


router = APIRouter(prefix="/oauth", tags=["OAuth & Social Sign-In"])


class IntrospectionRequest(BaseModel):
    token: str = Field(..., description="The string value of the token to introspect")
    token_type_hint: Optional[str] = Field(None, description="Hint: 'access_token' or 'refresh_token'")


class RevocationRequest(BaseModel):
    token: str = Field(..., description="The string value of the token to revoke")
    token_type_hint: Optional[str] = Field(None, description="Hint: 'access_token' or 'refresh_token'")


@router.post(
    "/introspect",
    summary="RFC 7662 Token Introspection",
    description="Determines active state and meta-information of a token for resource servers.",
)
async def introspect_token(
    payload: IntrospectionRequest,
    db: AsyncSession = Depends(get_db),
) -> Dict[str, Any]:
    return await token_introspection_service.introspect(
        db=db,
        token=payload.token,
        token_type_hint=payload.token_type_hint,
    )


@router.post(
    "/revoke",
    response_model=MessageResponse,
    summary="RFC 7009 Token Revocation",
    description="Revokes an active access token or refresh token.",
)
async def revoke_token(
    payload: RevocationRequest,
    db: AsyncSession = Depends(get_db),
):
    await token_introspection_service.revoke(
        db=db,
        token=payload.token,
        token_type_hint=payload.token_type_hint,
    )
    return MessageResponse(message="Token successfully revoked.")
