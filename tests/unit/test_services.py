"""Unit Tests for Domain Services (Email, Audit SIEM, Tenant Isolation, Session Device Tracking)."""

import pytest
from auth_service.services.email_service import email_service
from auth_service.services.audit_service import siem_audit_service, AuditSeverity
from auth_service.services.tenant_isolation_service import tenant_isolation_service
from auth_service.services.session_service import session_service
from auth_service.models.audit_log import AuditLog
from auth_service.core.exceptions import AuthorizationError, ValidationError


@pytest.mark.asyncio
async def test_email_service_dispatch():
    email = "notify@example.com"
    res1 = await email_service.send_verification_email(email, "verify_token_123")
    assert res1 is True

    res2 = await email_service.send_password_reset_email(email, "reset_token_456")
    assert res2 is True

    res3 = await email_service.send_account_locked_alert(email, 15)
    assert res3 is True
    assert len(email_service.sent_emails) >= 3


def test_siem_audit_formatting():
    log = AuditLog(
        id="audit-uuid-1",
        tenant_id="tenant-1",
        user_id="user-1",
        event_type="login",
        status="failed",
        ip_address="192.168.1.1",
        user_agent="Mozilla/5.0",
    )
    formatted = siem_audit_service.format_siem_event(log)
    assert formatted["event_id"] == "audit-uuid-1"
    assert formatted["severity"] == AuditSeverity.WARNING.value
    assert formatted["client"]["ip"] == "192.168.1.1"

    sev_critical = siem_audit_service.classify_severity("token_reuse_attack", "blocked")
    assert sev_critical == AuditSeverity.CRITICAL


def test_tenant_isolation_service():
    # Matching tenants pass
    tenant_isolation_service.verify_tenant_boundary("org-123", "org-123")

    # Mismatched tenants raise AuthorizationError
    with pytest.raises(AuthorizationError):
        tenant_isolation_service.verify_tenant_boundary("org-123", "org-456")

    # Check quotas
    tenant_isolation_service.check_quota("starter", "users", current_count=5)
    with pytest.raises(ValidationError):
        tenant_isolation_service.check_quota("starter", "users", current_count=10)


def test_session_service_fingerprinting():
    fp1 = session_service.compute_device_fingerprint("Mozilla/5.0", "192.168.1.1")
    fp2 = session_service.compute_device_fingerprint("Mozilla/5.0", "192.168.1.1")
    fp3 = session_service.compute_device_fingerprint("iPhone", "192.168.1.2")
    assert fp1 == fp2
    assert fp1 != fp3

    assert "iOS" in session_service.parse_device_name("iPhone Mobile")
    assert "Android" in session_service.parse_device_name("Android 14")
    assert "macOS" in session_service.parse_device_name("Macintosh; Intel Mac OS X")
    assert "Windows" in session_service.parse_device_name("Windows NT 10.0")

