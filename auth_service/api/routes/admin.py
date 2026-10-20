"""Administrative Dashboard & Observability API Router (Layer 5: API).

Provides administrative control over users, lockouts, audit log inspection, CSV exports,
and platform telemetry analytics.
"""

from datetime import datetime
from typing import List, Optional
from fastapi import APIRouter, Depends, Query, Response, status
from sqlalchemy.ext.asyncio import AsyncSession
from auth_service.core.dependencies import (
    get_current_active_user,
    get_db,
    get_tenant_id,
    require_permission,
    require_role,
)
from auth_service.core.exceptions import ResourceNotFoundError
from auth_service.core.security.lockout import lockout_manager
from auth_service.models.user import User
from auth_service.storage.postgres.audit_log_repo import AuditLogRepository
from auth_service.storage.postgres.role_repo import RoleRepository
from auth_service.storage.postgres.user_repo import UserRepository
from auth_service.api.schemas.admin_schemas import (
    AdminUserUpdateRequest,
    AnalyticsEventCount,
    AnalyticsOverviewResponse,
    AuditLogResponse,
)
from auth_service.api.schemas.common import MessageResponse, PaginatedResponse
from auth_service.api.schemas.user_schemas import RoleSummary, UserResponse


router = APIRouter(prefix="/admin", tags=["Administration & Telemetry"])


def serialize_user(user: User) -> UserResponse:
    roles_summary = [
        RoleSummary(id=r.id, name=r.name, description=r.description)
        for r in user.roles
    ]
    return UserResponse(
        id=user.id,
        email=user.email,
        full_name=user.full_name,
        avatar_url=user.avatar_url,
        is_active=user.is_active,
        is_verified=user.is_verified,
        is_superuser=user.is_superuser,
        tenant_id=user.tenant_id,
        roles=roles_summary,
        created_at=user.created_at,
        last_login_at=user.last_login_at,
    )


@router.get(
    "/users",
    response_model=PaginatedResponse[UserResponse],
    summary="List Users (Administrative)",
    description="Paginated list of users across the organization with flexible search and status filtering.",
)
async def admin_list_users(
    skip: int = Query(0, ge=0),
    limit: int = Query(50, ge=1, le=100),
    search: Optional[str] = Query(None),
    is_active: Optional[bool] = Query(None),
    tenant_id: str = Depends(get_tenant_id),
    current_user: User = Depends(require_permission("users:manage")),
    db: AsyncSession = Depends(get_db),
):
    user_repo = UserRepository(db)
    users, total = await user_repo.list_users(
        tenant_id=tenant_id,
        skip=skip,
        limit=limit,
        search=search,
        is_active=is_active,
    )
    items = [serialize_user(u) for u in users]
    return PaginatedResponse.create(items=items, total=total, skip=skip, limit=limit)


@router.get(
    "/users/{user_id}",
    response_model=UserResponse,
    summary="Get User Administrative Details",
    description="Full inspection of user account record by UUID.",
)
async def admin_get_user(
    user_id: str,
    tenant_id: str = Depends(get_tenant_id),
    current_user: User = Depends(require_permission("users:manage")),
    db: AsyncSession = Depends(get_db),
):
    user_repo = UserRepository(db)
    user = await user_repo.get_by_id(user_id, tenant_id=tenant_id)
    if not user:
        raise ResourceNotFoundError(f"User '{user_id}' not found")
    return serialize_user(user)


@router.put(
    "/users/{user_id}",
    response_model=UserResponse,
    summary="Admin Update User Account",
    description="Updates user attributes, toggles verification or active state, and binds roles.",
)
async def admin_update_user(
    user_id: str,
    payload: AdminUserUpdateRequest,
    tenant_id: str = Depends(get_tenant_id),
    current_user: User = Depends(require_permission("users:manage")),
    db: AsyncSession = Depends(get_db),
):
    user_repo = UserRepository(db)
    role_repo = RoleRepository(db)

    user = await user_repo.get_by_id(user_id, tenant_id=tenant_id)
    if not user:
        raise ResourceNotFoundError(f"User '{user_id}' not found")

    update_kwargs = {}
    if payload.full_name is not None:
        update_kwargs["full_name"] = payload.full_name
    if payload.is_active is not None:
        update_kwargs["is_active"] = payload.is_active
    if payload.is_verified is not None:
        update_kwargs["is_verified"] = payload.is_verified
    if payload.is_superuser is not None:
        update_kwargs["is_superuser"] = payload.is_superuser

    if update_kwargs:
        user = await user_repo.update(user_id, tenant_id=tenant_id, **update_kwargs)

    if payload.role_names is not None:
        new_roles = []
        for rname in payload.role_names:
            role = await role_repo.get_by_name(tenant_id, rname)
            if role:
                new_roles.append(role)
        user.roles = new_roles
        await db.flush()

    return serialize_user(user)


@router.post(
    "/users/{user_id}/lock",
    response_model=MessageResponse,
    summary="Manually Lock User Account",
    description="Applies administrative lockout suspension on an account.",
)
async def admin_lock_user(
    user_id: str,
    tenant_id: str = Depends(get_tenant_id),
    current_user: User = Depends(require_permission("users:manage")),
    db: AsyncSession = Depends(get_db),
):
    user_repo = UserRepository(db)
    user = await user_repo.get_by_id(user_id, tenant_id=tenant_id)
    if not user:
        raise ResourceNotFoundError(f"User '{user_id}' not found")

    # Record maximum failed attempts to trigger lockout in Redis
    await lockout_manager.record_failed_attempt(user.email)
    await lockout_manager.record_failed_attempt(user.email)
    await lockout_manager.record_failed_attempt(user.email)
    await lockout_manager.record_failed_attempt(user.email)
    await lockout_manager.record_failed_attempt(user.email)

    return MessageResponse(message=f"User '{user.email}' account has been locked.")


@router.post(
    "/users/{user_id}/unlock",
    response_model=MessageResponse,
    summary="Manually Unlock User Account",
    description="Clears brute-force failure counters and removes lockout status.",
)
async def admin_unlock_user(
    user_id: str,
    tenant_id: str = Depends(get_tenant_id),
    current_user: User = Depends(require_permission("users:manage")),
    db: AsyncSession = Depends(get_db),
):
    user_repo = UserRepository(db)
    user = await user_repo.get_by_id(user_id, tenant_id=tenant_id)
    if not user:
        raise ResourceNotFoundError(f"User '{user_id}' not found")

    await lockout_manager.unlock_account(user.email)
    return MessageResponse(message=f"User '{user.email}' account has been unlocked.")


@router.delete(
    "/users/{user_id}",
    response_model=MessageResponse,
    summary="Deactivate User Account",
    description="Soft-deletes user account and revokes access privileges.",
)
async def admin_delete_user(
    user_id: str,
    tenant_id: str = Depends(get_tenant_id),
    current_user: User = Depends(require_permission("users:manage")),
    db: AsyncSession = Depends(get_db),
):
    user_repo = UserRepository(db)
    await user_repo.delete(user_id, tenant_id=tenant_id, soft_delete=True)
    return MessageResponse(message=f"User '{user_id}' successfully deactivated.")


@router.get(
    "/audit-logs",
    response_model=PaginatedResponse[AuditLogResponse],
    summary="Query Audit Logs",
    description="Search immutable compliance audit logs with event type, date range, and status filters.",
)
async def admin_audit_logs(
    skip: int = Query(0, ge=0),
    limit: int = Query(50, ge=1, le=100),
    user_id: Optional[str] = Query(None),
    event_type: Optional[str] = Query(None),
    status: Optional[str] = Query(None),
    tenant_id: str = Depends(get_tenant_id),
    current_user: User = Depends(require_permission("audit:read")),
    db: AsyncSession = Depends(get_db),
):
    audit_repo = AuditLogRepository(db)
    logs, total = await audit_repo.query(
        tenant_id=tenant_id,
        user_id=user_id,
        event_type=event_type,
        status=status,
        skip=skip,
        limit=limit,
    )
    items = [
        AuditLogResponse(
            id=log.id,
            tenant_id=log.tenant_id,
            user_id=log.user_id,
            event_type=log.event_type,
            ip_address=log.ip_address,
            user_agent=log.user_agent,
            status=log.status,
            details=log.details,
            created_at=log.created_at,
        )
        for log in logs
    ]
    return PaginatedResponse.create(items=items, total=total, skip=skip, limit=limit)


@router.get(
    "/audit-logs/export",
    summary="Export Audit Logs as CSV",
    description="Generates and streams a CSV document containing compliance audit logs.",
)
async def export_audit_logs_csv(
    event_type: Optional[str] = Query(None),
    limit: int = Query(5000, ge=1, le=10000),
    tenant_id: str = Depends(get_tenant_id),
    current_user: User = Depends(require_permission("audit:export")),
    db: AsyncSession = Depends(get_db),
):
    audit_repo = AuditLogRepository(db)
    csv_data = await audit_repo.export_csv(
        tenant_id=tenant_id,
        event_type=event_type,
        limit=limit,
    )
    return Response(
        content=csv_data,
        media_type="text/csv",
        headers={"Content-Disposition": "attachment; filename=audit_logs.csv"},
    )


@router.get(
    "/analytics/overview",
    response_model=AnalyticsOverviewResponse,
    summary="Platform Analytics Overview",
    description="Aggregates high-level metrics for logins, registrations, and password recoveries.",
)
async def analytics_overview(
    days: int = Query(7, ge=1, le=90),
    tenant_id: str = Depends(get_tenant_id),
    current_user: User = Depends(require_permission("analytics:read")),
    db: AsyncSession = Depends(get_db),
):
    audit_repo = AuditLogRepository(db)
    summary = await audit_repo.get_analytics_summary(tenant_id=tenant_id, days=days)
    return AnalyticsOverviewResponse(**summary)


@router.get(
    "/analytics/events",
    response_model=List[AnalyticsEventCount],
    summary="Event Breakdown by Category",
    description="Returns event distribution and counts grouped by event category.",
)
async def analytics_events(
    days: int = Query(7, ge=1, le=90),
    tenant_id: str = Depends(get_tenant_id),
    current_user: User = Depends(require_permission("analytics:read")),
    db: AsyncSession = Depends(get_db),
):
    audit_repo = AuditLogRepository(db)
    counts = await audit_repo.get_event_counts_by_type(tenant_id=tenant_id, days=days)
    return [AnalyticsEventCount(**c) for c in counts]
