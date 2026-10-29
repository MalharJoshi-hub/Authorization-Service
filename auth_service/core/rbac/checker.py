"""RBAC Permission & Role Evaluator (Layer 3).

Enforces role-based access control and granular permission trees.
Provides wildcard resolution, role inheritance evaluation, and FastAPI route guards.
"""

from typing import Iterable, List, Set, Union
from auth_service.core.exceptions import AuthorizationError
from auth_service.core.logger import logger


# Role hierarchy definition (higher roles implicitly inherit subordinate capabilities)
ROLE_HIERARCHY = {
    "superadmin": {"admin", "editor", "member", "viewer"},
    "admin": {"editor", "member", "viewer"},
    "editor": {"member", "viewer"},
    "member": {"viewer"},
    "viewer": set(),
}


class RBACChecker:
    """Evaluates roles, role hierarchies, and permission trees against required policies."""

    @staticmethod
    def match_permission(granted: str, required: str) -> bool:
        """Evaluate if a granted permission string covers the required permission.

        Supports:
          - Exact match: 'users:read' == 'users:read'
          - Global wildcard: '*' matches all permissions
          - Administrative wildcard: 'admin:*' matches all operations
          - Resource wildcard: 'users:*' matches 'users:read', 'users:delete'
          - Action wildcard: '*:read' matches 'users:read', 'roles:read'
        """
        g = granted.strip().lower()
        r = required.strip().lower()

        if g == "*" or g == "admin:*" or g == r:
            return True

        if g.endswith(":*"):
            resource_prefix = g[:-2]
            if r.startswith(f"{resource_prefix}:"):
                return True

        if g.startswith("*:") and r.endswith(g[1:]):
            return True

        return False

    @classmethod
    def has_permission(cls, granted_permissions: Iterable[str], required_permission: str) -> bool:
        """Check if any granted permission satisfies the required permission."""
        for p in granted_permissions:
            if cls.match_permission(p, required_permission):
                return True
        return False

    @classmethod
    def has_all_permissions(cls, granted_permissions: Iterable[str], required_permissions: Iterable[str]) -> bool:
        """Verify that all required permissions are satisfied."""
        return all(cls.has_permission(granted_permissions, req) for req in required_permissions)

    @classmethod
    def has_role(cls, assigned_roles: Iterable[str], required_role: str) -> bool:
        """Evaluate if assigned roles satisfy required role, including hierarchy inheritance."""
        req = required_role.strip().lower()
        assigned_set = {r.strip().lower() for r in assigned_roles}

        # Direct assignment match
        if req in assigned_set:
            return True

        # Inheritance match (e.g. 'superadmin' satisfies 'admin')
        for assigned in assigned_set:
            inherited = ROLE_HIERARCHY.get(assigned, set())
            if req in inherited:
                return True

        return False


rbac_checker = RBACChecker()
has_permission = RBACChecker.has_permission
has_role = RBACChecker.has_role
check_permissions = RBACChecker.has_all_permissions

