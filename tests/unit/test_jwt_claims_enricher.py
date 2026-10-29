"""Unit tests for dynamic JWT claims enrichment."""

import pytest
from auth_service.core.security.jwt_claims_enricher import ClaimsEnricher
from auth_service.models.permission import Permission
from auth_service.models.role import Role
from auth_service.models.user import User


def test_build_claims_basic():
    enricher = ClaimsEnricher()
    user = User(
        id="usr-12345",
        email="test@domain.com",
        tenant_id="tenant-alpha",
        is_verified=True,
    )

    claims = enricher.build_claims(user, auth_method="pwd")
    assert claims["sub"] == "usr-12345"
    assert claims["email"] == "test@domain.com"
    assert claims["tenant_id"] == "tenant-alpha"
    assert claims["amr"] == ["pwd"]
    assert claims["is_verified"] is True


def test_build_claims_with_roles_and_mfa():
    enricher = ClaimsEnricher()

    p1 = Permission(name="read:reports", resource="reports", action="read")
    p2 = Permission(name="write:reports", resource="reports", action="write")
    r1 = Role(name="report_viewer", tenant_id="tenant-alpha", permissions=[p1])
    r2 = Role(name="report_editor", tenant_id="tenant-alpha", permissions=[p1, p2])

    user = User(
        id="usr-9999",
        email="analyst@domain.com",
        tenant_id="tenant-alpha",
        roles=[r1, r2],
    )

    claims = enricher.build_claims(user, auth_method="pwd")
    assert "report_viewer" in claims["roles"]
    assert "report_editor" in claims["roles"]
    assert "read:reports" in claims["permissions"]
    assert "write:reports" in claims["permissions"]


def test_enrichment_hook():
    enricher = ClaimsEnricher()

    def custom_hook(claims, user):
        claims["tier"] = "enterprise"

    enricher.register_hook(custom_hook)

    user = User(id="u1", email="u1@org.io", tenant_id="t1")
    claims = enricher.build_claims(user)
    assert claims.get("tier") == "enterprise"
