"""Authorization and Role-Based Access Control Subsystem (Layer 3).

Exposes role verification, permission evaluation, and wildcard matchers.
"""

from auth_service.core.rbac.checker import (
    RBACChecker,
    rbac_checker,
    has_role,
    has_permission,
)
from auth_service.core.rbac.permissions import (
    SystemPermissions,
    ALL_SYSTEM_PERMISSIONS,
)

__all__ = [
    "RBACChecker",
    "rbac_checker",
    "has_role",
    "has_permission",
    "SystemPermissions",
    "ALL_SYSTEM_PERMISSIONS",
]

