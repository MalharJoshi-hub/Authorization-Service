"""Deep unit tests for database models, mixins, serializers, and relationships."""

import pytest
from datetime import datetime, timezone
from auth_service.models.user import User
from auth_service.models.role import Role
from auth_service.models.permission import Permission
from auth_service.models.tenant import Tenant
from auth_service.models.api_key import APIKey
from auth_service.models.audit_log import AuditLog
from auth_service.models.session import UserSession
from auth_service.models.token import RefreshToken
from auth_service.models.oauth_account import OAuthAccount
from auth_service.models.webhook import WebhookEndpoint


def test_user_model_instantiation_and_repr():
    user = User(
        email="dev@auth-service.io",
        hashed_password="bcrypt_hashed_value",
        full_name="Developer User",
        tenant_id="tenant-primary",
        is_active=True,
        is_verified=True,
    )
    assert user.email == "dev@auth-service.io"
    assert user.username == "dev"
    assert repr(user).startswith("<User ")
    d = user.to_dict()
    assert d["email"] == "dev@auth-service.io"


def test_role_and_permission_models():
    perm = Permission(name="read:reports", resource="reports", action="read", description="Can read reports")
    assert perm.name == "read:reports"
    assert repr(perm).startswith("<Permission ")
    perm_dict = perm.to_dict()
    assert perm_dict["action"] == "read"

    role = Role(name="report_viewer", tenant_id="t-1", description="Viewer role", is_system=False)
    role.permissions.append(perm)
    assert repr(role).startswith("<Role ")
    assert len(role.permissions) == 1


def test_tenant_model():
    tenant = Tenant(
        name="Enterprise Beta",
        slug="enterprise-beta",
        plan="enterprise",
        is_active=True,
        settings_json='{"sso_enforced": true}',
    )
    assert repr(tenant).startswith("<Tenant ")
    td = tenant.to_dict()
    assert td["slug"] == "enterprise-beta"
    assert td["plan"] == "enterprise"


def test_api_key_model():
    key = APIKey(
        name="CI Service Worker",
        key_hash="sha256_hash_value_here",
        prefix="aaas_live_a1b2",
        tenant_id="t-1",
        scopes_json='["read:users", "write:users"]',
        is_active=True,
    )
    assert repr(key).startswith("<APIKey ")
    kd = key.to_dict()
    assert kd["prefix"] == "aaas_live_a1b2"
    assert "read:users" in key.scopes


def test_audit_log_model():
    log = AuditLog(
        tenant_id="tenant-1",
        user_id="user-1",
        event_type="user.login.success",
        status="success",
        ip_address="127.0.0.1",
        user_agent="pytest-client",
        details_json='{"method": "password"}',
    )
    assert repr(log).startswith("<AuditLog ")
    ld = log.to_dict()
    assert ld["event_type"] == "user.login.success"
    assert log.action == "user.login.success"
    assert ld["ip_address"] == "127.0.0.1"


def test_user_session_model():
    now = datetime.now(timezone.utc)
    sess = UserSession(
        user_id="user-xyz",
        tenant_id="tenant-xyz",
        device_name="MacBook Pro",
        device_fingerprint="abc123fingerprint",
        ip_address="10.0.0.1",
        is_active=True,
        expires_at=now,
    )
    assert repr(sess).startswith("<UserSession ")
    sd = sess.to_dict()
    assert sd["device_name"] == "MacBook Pro"
    assert sd["is_active"] is True


def test_refresh_token_model():
    now = datetime.now(timezone.utc)
    tok = RefreshToken(
        token_hash="hash_token_abc",
        user_id="u1",
        tenant_id="t1",
        family_id="fam-1",
        is_revoked=False,
        expires_at=now,
    )
    assert repr(tok).startswith("<RefreshToken ")
    td = tok.to_dict()
    assert td["family_id"] == "fam-1"
    assert td["is_revoked"] is False


def test_oauth_account_model():
    oauth = OAuthAccount(
        user_id="u1",
        provider="github",
        provider_user_id="12345678",
        email="oauth@github.com",
    )
    assert repr(oauth).startswith("<OAuthAccount ")
    od = oauth.to_dict()
    assert od["provider"] == "github"
    assert od["provider_user_id"] == "12345678"


def test_webhook_subscription_model():
    wh = WebhookEndpoint(
        tenant_id="t1",
        url="https://api.external.com/webhooks",
        secret="whsec_123456789",
        events_json='["user.created", "token.revoked"]',
        is_active=True,
    )
    assert repr(wh).startswith("<WebhookEndpoint ")
    wd = wh.to_dict()
    assert wd["url"] == "https://api.external.com/webhooks"
    assert "user.created" in wh.subscribed_events
