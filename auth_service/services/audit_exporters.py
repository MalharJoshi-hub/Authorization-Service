"""Enterprise Compliance Audit Exporters (Layer 4 & Layer 5).

Exports immutable audit records to RFC 5424 Syslog, JSON-Lines rotated logfiles,
and streaming telemetry destinations for SOC2 / ISO 27001 compliance.
"""

import json
from datetime import datetime, timezone
from typing import Any, Dict, List
from auth_service.models.audit_log import AuditLog
from auth_service.services.audit_service import siem_audit_service


class SyslogRFC5424Exporter:
    """Formats audit log records according to RFC 5424 Syslog protocol."""

    FACILITY_AUTH = 4  # security/authorization messages
    FACILITY_AUTHPRIV = 10  # security/authorization messages (private)

    @classmethod
    def format_syslog_message(
        cls,
        log: AuditLog,
        hostname: str = "aas-node-1",
        app_name: str = "AaaS",
    ) -> str:
        """Format RFC 5424 message: <PRI>VERSION TIMESTAMP HOSTNAME APPNAME PROCID MSGID STRUCTURED-DATA MSG."""
        # Calculate PRI = (facility * 8) + severity
        pri = (cls.FACILITY_AUTHPRIV * 8) + 6  # informational
        ts = log.created_at.isoformat() if log.created_at else datetime.now(timezone.utc).isoformat()
        msg_id = log.event_type.upper()
        sd = f'[audit@32473 tenantId="{log.tenant_id}" userId="{log.user_id or ""}" status="{log.status}"]'
        msg = f"Security Event {log.event_type} from {log.ip_address or 'unknown'}: {log.details_json}"

        return f"<{pri}>1 {ts} {hostname} {app_name} - {msg_id} {sd} {msg}"


class JSONLinesExporter:
    """Serializes collections of audit logs to JSON Lines (JSONL) strings."""

    @staticmethod
    def export_jsonl(logs: List[AuditLog]) -> str:
        """Serialize audit logs into line-delimited JSON format."""
        lines = []
        for log in logs:
            siem_dict = siem_audit_service.format_siem_event(log)
            lines.append(json.dumps(siem_dict))
        return "\n".join(lines)


syslog_exporter = SyslogRFC5424Exporter()
jsonl_exporter = JSONLinesExporter()
