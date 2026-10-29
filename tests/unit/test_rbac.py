"""Unit Tests for Role-Based Access Control and Hierarchies (Phase 8: Layer 3)."""

from auth_service.core.rbac.checker import rbac_checker, has_role, has_permission


def test_rbac_match_permission():
    # Exact match
    assert rbac_checker.match_permission("users:read", "users:read") is True
    assert rbac_checker.match_permission("users:read", "users:write") is False

    # Superuser and admin wildcards
    assert rbac_checker.match_permission("*", "any:perm") is True
    assert rbac_checker.match_permission("admin:*", "users:delete") is True

    # Resource wildcards
    assert rbac_checker.match_permission("users:*", "users:read") is True
    assert rbac_checker.match_permission("users:*", "users:delete") is True
    assert rbac_checker.match_permission("users:*", "roles:read") is False

    # Action wildcards
    assert rbac_checker.match_permission("*:read", "users:read") is True
    assert rbac_checker.match_permission("*:read", "audit:read") is True
    assert rbac_checker.match_permission("*:read", "users:write") is False


def test_rbac_has_permission():
    granted = ["users:read", "roles:*"]
    assert has_permission(granted, "users:read") is True
    assert has_permission(granted, "roles:create") is True
    assert has_permission(granted, "audit:read") is False


def test_rbac_has_role_direct_and_hierarchy():
    # Direct match
    assert has_role(["admin"], "admin") is True
    assert has_role(["viewer"], "viewer") is True

    # Hierarchy inheritance
    # superadmin inherits admin, editor, member, viewer
    assert has_role(["superadmin"], "admin") is True
    assert has_role(["superadmin"], "viewer") is True

    # admin inherits editor, member, viewer
    assert has_role(["admin"], "member") is True
    assert has_role(["admin"], "viewer") is True
    assert has_role(["admin"], "superadmin") is False

    # viewer inherits nothing higher
    assert has_role(["viewer"], "admin") is False
    assert has_role(["viewer"], "member") is False
