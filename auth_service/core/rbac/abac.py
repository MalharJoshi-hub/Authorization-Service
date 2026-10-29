"""Attribute-Based Access Control (ABAC) Policy Evaluator (Layer 3).

Complements role-based access control with fine-grained contextual evaluation of
resource ownership, environmental conditions, and client network origin.
"""

from datetime import datetime, time
from typing import Any, Dict, Optional
from auth_service.core.exceptions import AuthorizationError


class ABACRuleEvaluator:
    """Evaluates contextual environmental attributes alongside RBAC role grants."""

    @staticmethod
    def is_resource_owner(requester_user_id: str, resource_owner_id: Optional[str]) -> bool:
        """Verify whether requester is the owner of the target resource."""
        if not resource_owner_id or not requester_user_id:
            return False
        return str(requester_user_id) == str(resource_owner_id)

    @staticmethod
    def is_within_business_hours(
        current_time: Optional[time] = None,
        start_hour: int = 8,
        end_hour: int = 19,
    ) -> bool:
        """Evaluate if current request falls within organization operating hours."""
        t = current_time or datetime.now().time()
        start = time(start_hour, 0)
        end = time(end_hour, 0)
        return start <= t <= end

    @classmethod
    def evaluate_access(
        cls,
        user_id: str,
        resource: Dict[str, Any],
        context: Dict[str, Any],
        require_ownership: bool = False,
    ) -> bool:
        """Run comprehensive ABAC policy validation."""
        # 1. Ownership evaluation
        if require_ownership:
            owner_id = resource.get("owner_id") or resource.get("user_id")
            if not cls.is_resource_owner(user_id, owner_id):
                raise AuthorizationError(
                    "ABAC Policy Rejection: You do not have ownership of this resource",
                    code="OWNERSHIP_REQUIRED",
                )

        # 2. IP Whitelist constraint check if defined on resource
        allowed_cidrs = resource.get("allowed_cidrs")
        if allowed_cidrs:
            client_ip = context.get("client_ip")
            if client_ip not in allowed_cidrs:
                raise AuthorizationError(
                    "ABAC Policy Rejection: Client IP is not permitted for this resource",
                    code="IP_NOT_PERMITTED",
                )

        return True


abac_evaluator = ABACRuleEvaluator()


class ABACContext:
    """Environmental and user context attributes for dynamic policy evaluation."""

    def __init__(self, **kwargs):
        for k, v in kwargs.items():
            setattr(self, k, v)

    def __getattr__(self, name):
        return None


class ABACEngine:
    """Dynamic policy evaluation engine."""

    def __init__(self):
        self._rules = {}

    def register_rule(self, name: str, fn) -> None:
        self._rules[name] = fn

    def evaluate(self, name: str, ctx: ABACContext) -> bool:
        if name in self._rules:
            return bool(self._rules[name](ctx))
        return False

    def evaluate_all(self, names: list, ctx: ABACContext) -> bool:
        return all(self.evaluate(n, ctx) for n in names)


ABACRule = ABACRuleEvaluator

