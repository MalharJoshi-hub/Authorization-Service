"""Comprehensive services layer matrix tests."""

import pytest
import hmac
import hashlib
from datetime import datetime, timedelta, timezone

from auth_service.services.mfa_service import MFAService
from auth_service.services.session_service import SessionService
from auth_service.services.webhook_service import WebhookService
from auth_service.services.email_service import EmailService
from auth_service.services.ip_intelligence_service import IPIntelligenceService
from auth_service.services.tenant_isolation_service import TenantIsolationService
from auth_service.core.exceptions import AuthorizationError


def test_mfa_service_secret_and_qr():
    service = MFAService()
    secret = service.generate_secret()
    assert len(secret) >= 16

    uri = service.get_totp_uri(secret=secret, email="user@matrix.io", issuer="MatrixAuth")
    assert uri.startswith("otpauth://totp/")
    assert "user%40matrix.io" in uri or "user@matrix.io" in uri
    assert "secret=" in uri


def test_webhook_signature_generation():
    service = WebhookService()
    secret = "whsec_test_secret_12345"
    payload = '{"event": "user.created", "user_id": "u-123"}'

    signature = service.generate_signature(payload, secret)
    assert signature is not None

    expected_sig = hmac.new(secret.encode("utf-8"), payload.encode("utf-8"), hashlib.sha256).hexdigest()
    assert signature == expected_sig


def test_email_service_token_url_builders():
    service = EmailService()
    verify_url = service.build_verification_url("token_abc_123")
    assert "token=token_abc_123" in verify_url
    assert "/verify-email" in verify_url

    reset_url = service.build_reset_password_url("reset_token_xyz")
    assert "token=reset_token_xyz" in reset_url
    assert "/reset-password" in reset_url


def test_ip_intelligence_internal_and_loopback():
    service = IPIntelligenceService()

    # Loopback
    res_loopback = service.analyze_ip("127.0.0.1")
    assert res_loopback.is_private is True
    assert res_loopback.risk_score == 0

    # Private RFC 1918
    res_private = service.analyze_ip("192.168.1.100")
    assert res_private.is_private is True
    assert res_private.risk_score == 0

    # Public IP
    res_public = service.analyze_ip("8.8.8.8")
    assert res_public.is_private is False
    assert res_public.risk_score <= 20


def test_tenant_isolation_service_enforcement():
    service = TenantIsolationService()

    # Same tenant allowed
    assert service.validate_access(current_tenant_id="tenant-alpha", target_tenant_id="tenant-alpha") is True

    # Cross tenant blocked
    with pytest.raises(AuthorizationError):
        service.validate_access(current_tenant_id="tenant-alpha", target_tenant_id="tenant-beta")


@pytest.mark.asyncio
async def test_session_service_device_management(db_session, test_tenant, test_user):
    service = SessionService(db_session)

    # Create session
    sess = await service.create_session(
        user_id=test_user.id,
        tenant_id=test_tenant.id,
        ip_address="192.168.0.50",
        user_agent="Mozilla/5.0 Matrix Test",
        device_fingerprint="matrix_fp_999",
    )
    assert sess.id is not None
    assert sess.is_active is True

    # List active
    active = await service.get_active_sessions(test_user.id)
    assert any(s.id == sess.id for s in active)

    # Revoke session
    revoked = await service.revoke_session(sess.id, test_user.id)
    assert revoked is True

