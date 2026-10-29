"""API Key and Token Scope Hierarchy Evaluator (Layer 1).

Implements granular scope validation with wildcard and hierarchical matching
conforming to OAuth 2.0 and API security best practices.
"""

from typing import Iterable, List, Set


STANDARD_SCOPES = {
    "read:users": "Read user profiles and public directory data",
    "write:users": "Create, update, and manage user accounts",
    "read:roles": "View role configurations and assigned permissions",
    "write:roles": "Create and modify roles and permission grants",
    "manage:api_keys": "Issue, list, and revoke machine API keys",
    "read:audit": "View tamper-evident security audit logs",
    "export:audit": "Export compliance audit trails to CSV/JSON",
    "read:analytics": "Access system and authentication telemetry",
    "manage:tenants": "Create, configure, and administrate tenant organizations",
    "admin:*": "Full administrative privilege across all platform resources",
    "*": "Superuser wildcard granting unrestricted system access",
}


def match_scope(granted_scope: str, requested_scope: str) -> bool:
    """Evaluate whether a granted scope pattern covers the requested scope.

    Supports:
      - Exact match: 'read:users' matches 'read:users'
      - Global wildcard: '*' matches everything
      - Domain wildcard: 'admin:*' matches any 'admin:...' scope
      - Resource wildcard: 'users:*' matches 'users:read', 'users:write'
    """
    if granted_scope == "*" or granted_scope == requested_scope:
        return True

    # Wildcard suffix matching (e.g., 'users:*' matches 'users:read')
    if granted_scope.endswith(":*"):
        prefix = granted_scope[:-2]
        if requested_scope.startswith(prefix + ":") or requested_scope.startswith(prefix):
            return True

    # Reverse prefix format support (e.g., '*:read' matches 'users:read')
    if granted_scope.startswith("*:") and requested_scope.endswith(granted_scope[1:]):
        return True

    return False


def has_scope(assigned_scopes: Iterable[str], required_scope: str) -> bool:
    """Determine if a collection of granted scopes satisfies a required scope."""
    for scope in assigned_scopes:
        if match_scope(scope.strip(), required_scope.strip()):
            return True
    return False


def has_all_scopes(assigned_scopes: Iterable[str], required_scopes: Iterable[str]) -> bool:
    """Determine if all required scopes are satisfied by the granted scopes."""
    return all(has_scope(assigned_scopes, req) for req in required_scopes)


has_required_scope = has_scope
validate_scopes = has_all_scopes



def has_any_scope(assigned_scopes: Iterable[str], required_scopes: Iterable[str]) -> bool:
    """Determine if at least one required scope is satisfied by the granted scopes."""
    return any(has_scope(assigned_scopes, req) for req in required_scopes)
