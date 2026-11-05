"""Unit Tests for Scope Hierarchy Evaluation (Phase 8: Layer 1)."""

from auth_service.core.security.scopes import (
    match_scope,
    has_scope,
    has_all_scopes,
    has_any_scope,
)


def test_match_scope_exact_and_wildcards():
    # Exact match
    assert match_scope("read:users", "read:users") is True
    assert match_scope("read:users", "write:users") is False

    # Global wildcard
    assert match_scope("*", "read:users") is True
    assert match_scope("*", "anything:action") is True

    # Domain prefix wildcard
    assert match_scope("users:*", "users:read") is True
    assert match_scope("users:*", "users:write") is True
    assert match_scope("users:*", "roles:read") is False

    # Action suffix wildcard
    assert match_scope("*:read", "users:read") is True
    assert match_scope("*:read", "roles:read") is True
    assert match_scope("*:read", "users:write") is False


def test_has_scope_collection():
    granted = ["read:users", "write:users", "audit:*"]
    assert has_scope(granted, "read:users") is True
    assert has_scope(granted, "audit:export") is True
    assert has_scope(granted, "roles:delete") is False


def test_has_all_and_any_scopes():
    granted = ["read:users", "write:roles"]
    assert has_all_scopes(granted, ["read:users", "write:roles"]) is True
    assert has_all_scopes(granted, ["read:users", "delete:roles"]) is False
    assert has_any_scope(granted, ["nonexistent:scope", "write:roles"]) is True
    assert has_any_scope(granted, ["foo", "bar"]) is False

