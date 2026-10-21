"""SIEM & SOC2 Compliance Audit Logging Service (Layer 4 & Layer 5).

Categorizes security mutations, applies threat severity weighting (INFO, WARN, CRITICAL),
and formats structured audit payloads for enterprise SIEM ingestion (Splunk, Datadog).
"""

from datetime import datetime, timezone
from enum import Enum
from typing import Any, Dict, Optional
from auth_service.core.logger import logger
from auth_service.models.audit_log import AuditLog


class AuditSeverity(str, Enum):
    INFO = "INFO"
    NOTICE = "NOTICE"
    WARNING = "WARNING"
    ALERT = "ALERT"
    CRITICAL = "CRITICAL"


class AuditCategory(str, Enum):
    AUTHENTICATION = "AUTHENTICATION"
    AUTHORIZATION = "AUTHORIZATION"
    CREDENTIAL_MUTATION = "CREDENTIAL_MUTATION"
    POLICY_VIOLATION = "POLICY_VIOLATION"
    BRUTE_FORCE = "BRUTE_FORCE"
    SYSTEM_ADMIN = "SYSTEM_ADMIN"


EVENT_SEVERITY_MAP = {
    "login": AuditSeverity.INFO,
    "logout": AuditSeverity.INFO,
    "register": AuditSeverity.INFO,
    "email_verified": AuditSeverity.INFO,
    "token_refresh": AuditSeverity.INFO,
    "password_changed": AuditSeverity.NOTICE,
    "password_reset_requested": AuditSeverity.NOTICE,
    "password_reset_completed": AuditSeverity.WARNING,
    "api_key_created": AuditSeverity.NOTICE,
    "api_key_revoked": AuditSeverity.NOTICE,
    "account_locked": AuditSeverity.ALERT,
    "token_reuse_attack": AuditSeverity.CRITICAL,
    "unauthorized_access": AuditSeverity.WARNING,
}


class SIEMAuditService:
    """Formats and enriches audit events for enterprise SIEM compliance."""

    @staticmethod
    def classify_severity(event_type: str, status: str) -> AuditSeverity:
        """Derive severity classification from event and outcome."""
        if status == "failed" and event_type == "login":
            return AuditSeverity.WARNING
        return EVENT_SEVERITY_MAP.get(event_type, AuditSeverity.INFO)

    @classmethod
    def format_siem_event(cls, log: AuditLog) -> Dict[str, Any]:
        """Produce standardized CEF/JSON compliant event format."""
        severity = cls.classify_severity(log.event_type, log.status)
        return {
            "version": "1.0",
            "timestamp": log.created_at.isoformat() if log.created_at else datetime.now(timezone.utc).isoformat(),
            "event_id": log.id,
            "tenant_id": log.tenant_id,
            "user_id": log.user_id,
            "event_type": log.event_type,
            "severity": severity.value,
            "status": log.status,
            "client": {
                "ip": log.ip_address,
                "user_agent": log.user_agent,
            },
            "details": log.details,
        }


siem_audit_service = SIEMAuditService()
