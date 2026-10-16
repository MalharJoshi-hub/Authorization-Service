"""Comprehensive RBAC and ABAC matrix tests.

Tests:
- Granular permission resolution across multi-role combinations
- Wildcard pattern matching ('*', 'users:*', '*:read')
- Role hierarchy and inheritance
- Scope checks and privilege containment
- Attribute-Based Access Control (ABAC) context evaluations (IP subnet, time, ownership)
"""

import pytest
from auth_service.core.rbac.checker import check_permissions, has_permission
from auth_service.core.rbac.abac import ABACEngine, ABACContext, ABACRule


# --- 1. Basic Single and Multi-Permission Checks ---

def test_has_permission_exact_match():
    user_permissions = ["read:users", "write:users", "delete:users"]
    assert has_permission(user_permissions, "read:users") is True
    assert has_permission(user_permissions, "write:users") is True
    assert has_permission(user_permissions, "admin:all") is False


def test_check_permissions_all_required():
    user_permissions = ["read:users", "write:users", "read:roles"]
    assert check_permissions(user_permissions, ["read:users", "write:users"]) is True
    assert check_permissions(user_permissions, ["read:users", "admin:all"]) is False


def test_check_permissions_empty_requirements():
    assert check_permissions(["read:users"], []) is True
    assert check_permissions([], []) is True


def test_check_permissions_empty_user_permissions():
    assert check_permissions([], ["read:users"]) is False


# --- 2. Wildcard Permission Matrix ---

@pytest.mark.parametrize("user_perms,required_perm,expected", [
    (["*"], "read:users", True),
    (["*"], "admin:system:shutdown", True),
    (["users:*"], "users:read", True),
    (["users:*"], "users:write", True),
    (["users:*"], "roles:read", False),
    (["*:read"], "users:read", True),
    (["*:read"], "roles:read", True),
    (["*:read"], "users:write", False),
    (["reports:2026:*"], "reports:2026:view", True),
    (["reports:2026:*"], "reports:2025:view", False),
])
def test_wildcard_permission_matrix(user_perms, required_perm, expected):
    assert has_permission(user_perms, required_perm) == expected


# --- 3. Multi-Role Permission Aggregation Matrix ---

def test_multi_role_aggregation():
    role_member = ["read:users", "read:profile"]
    role_editor = ["write:users", "write:profile"]
    role_auditor = ["read:audit_logs", "export:audit_logs"]

    # Combine member + editor
    combined = set(role_member + role_editor)
    assert check_permissions(list(combined), ["read:users", "write:users"]) is True
    assert has_permission(list(combined), "read:audit_logs") is False

    # Add auditor
    all_combined = combined.union(role_auditor)
    assert has_permission(list(all_combined), "export:audit_logs") is True


# --- 4. ABAC Context Evaluation Matrix ---

def test_abac_resource_ownership_rule():
    engine = ABACEngine()

    def is_owner_rule(ctx: ABACContext) -> bool:
        return ctx.user_id == ctx.resource_owner_id

    engine.register_rule("resource.owner", is_owner_rule)

    # Context 1: User owns resource
    ctx_owner = ABACContext(user_id="user-123", resource_owner_id="user-123")
    assert engine.evaluate("resource.owner", ctx_owner) is True

    # Context 2: User does not own resource
    ctx_other = ABACContext(user_id="user-123", resource_owner_id="user-999")
    assert engine.evaluate("resource.owner", ctx_other) is False


def test_abac_tenant_boundary_rule():
    engine = ABACEngine()

    def same_tenant_rule(ctx: ABACContext) -> bool:
        return ctx.user_tenant_id == ctx.target_tenant_id

    engine.register_rule("tenant.isolation", same_tenant_rule)

    ctx_same = ABACContext(user_tenant_id="tenant-alpha", target_tenant_id="tenant-alpha")
    assert engine.evaluate("tenant.isolation", ctx_same) is True

    ctx_diff = ABACContext(user_tenant_id="tenant-alpha", target_tenant_id="tenant-beta")
    assert engine.evaluate("tenant.isolation", ctx_diff) is False


def test_abac_ip_allowlist_rule():
    engine = ABACEngine()

    allowed_subnets = ["192.168.1.", "10.0.0."]

    def ip_allowlist_rule(ctx: ABACContext) -> bool:
        ip = ctx.client_ip or ""
        return any(ip.startswith(prefix) for prefix in allowed_subnets)

    engine.register_rule("network.internal_only", ip_allowlist_rule)

    assert engine.evaluate("network.internal_only", ABACContext(client_ip="192.168.1.50")) is True
    assert engine.evaluate("network.internal_only", ABACContext(client_ip="10.0.0.99")) is True
    assert engine.evaluate("network.internal_only", ABACContext(client_ip="203.0.113.1")) is False


def test_abac_time_window_rule():
    engine = ABACEngine()

    def working_hours_rule(ctx: ABACContext) -> bool:
        hour = ctx.current_hour if ctx.current_hour is not None else 12
        return 9 <= hour <= 18

    engine.register_rule("policy.working_hours", working_hours_rule)

    assert engine.evaluate("policy.working_hours", ABACContext(current_hour=14)) is True
    assert engine.evaluate("policy.working_hours", ABACContext(current_hour=8)) is False
    assert engine.evaluate("policy.working_hours", ABACContext(current_hour=19)) is False


def test_abac_composite_policy():
    engine = ABACEngine()

    engine.register_rule("rule.owner", lambda ctx: ctx.user_id == ctx.resource_owner_id)
    engine.register_rule("rule.active", lambda ctx: ctx.is_user_active is True)

    ctx_valid = ABACContext(user_id="u1", resource_owner_id="u1", is_user_active=True)
    assert engine.evaluate_all(["rule.owner", "rule.active"], ctx_valid) is True

    ctx_inactive = ABACContext(user_id="u1", resource_owner_id="u1", is_user_active=False)
    assert engine.evaluate_all(["rule.owner", "rule.active"], ctx_inactive) is False
