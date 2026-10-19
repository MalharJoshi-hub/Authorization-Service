"""Multi-Tenant Isolation & Quota Enforcement Service (Layer 3).

Guarantees complete horizontal data isolation between organizations, validates
tenant context matching, and enforces plan quotas (maximum API keys, members, roles).
"""

from typing import Any, Dict
from auth_service.core.exceptions import AuthorizationError, ValidationError


PLAN_QUOTAS = {
    "starter": {"max_users": 10, "max_api_keys": 5, "max_roles": 5, "mfa_allowed": False},
    "standard": {"max_users": 100, "max_api_keys": 25, "max_roles": 20, "mfa_allowed": True},
    "enterprise": {"max_users": 10000, "max_api_keys": 500, "max_roles": 100, "mfa_allowed": True},
}


class TenantIsolationService:
    """Enforces tenant data boundaries and plan entitlement constraints."""

    @staticmethod
    def verify_tenant_boundary(resource_tenant_id: str, context_tenant_id: str) -> None:
        """Ensure the accessed resource strictly belongs to the authenticated tenant context.

        Raises:
            AuthorizationError: If tenant IDs do not match (cross-tenant data leakage attempt).
        """
        if resource_tenant_id != context_tenant_id:
            raise AuthorizationError(
                "Access Denied: Attempted to access resource outside of authenticated tenant boundary",
                code="CROSS_TENANT_ACCESS_DENIED",
            )

    @classmethod
    def validate_access(cls, current_tenant_id: str, target_tenant_id: str) -> bool:
        """Verify cross-tenant boundary access and raise AuthorizationError if mismatched."""
        cls.verify_tenant_boundary(resource_tenant_id=target_tenant_id, context_tenant_id=current_tenant_id)
        return True

    @staticmethod
    def get_plan_limits(plan_name: str) -> Dict[str, Any]:
        """Fetch resource quotas for a subscription tier."""
        return PLAN_QUOTAS.get(plan_name.lower(), PLAN_QUOTAS["standard"])

    @classmethod
    def check_quota(cls, plan_name: str, resource_type: str, current_count: int) -> None:
        """Validate current usage against plan ceiling."""
        limits = cls.get_plan_limits(plan_name)
        limit_key = f"max_{resource_type}"
        max_allowed = limits.get(limit_key)

        if max_allowed is not None and current_count >= max_allowed:
            raise ValidationError(
                f"Tenant plan quota reached: Maximum allowed {resource_type} is {max_allowed} for {plan_name} plan.",
                code="QUOTA_EXCEEDED",
            )


tenant_isolation_service = TenantIsolationService()
