"""Security Event Dispatcher and SIEM Integration Hub.

Publishes asynchronous security events (lockouts, impossible travel, token revocations,
admin actions, failed logins) to registered observers:
- In-memory event subscribers
- External SIEM sinks (Syslog, CloudWatch, Datadog, Elastic)
- Security alerting webhooks
"""

from __future__ import annotations

import asyncio
from datetime import datetime, timezone
from typing import Any, Callable, Coroutine, Dict, List, Optional

from auth_service.core.logger import get_logger

logger = get_logger("auth_service.services.security_events")

# Type alias for async event listeners
EventListener = Callable[[Dict[str, Any]], Coroutine[Any, Any, None]]


class SecurityEventType:
    """Standard security event categories."""

    LOGIN_SUCCESS = "auth.login.success"
    LOGIN_FAILED = "auth.login.failure"
    ACCOUNT_LOCKED = "auth.account.locked"
    ACCOUNT_UNLOCKED = "auth.account.unlocked"
    PASSWORD_CHANGED = "auth.password.changed"
    MFA_ENABLED = "auth.mfa.enabled"
    MFA_FAILED = "auth.mfa.failure"
    TOKEN_REVOKED = "auth.token.revoked"
    TOKEN_REPLAY_ATTEMPT = "auth.token.replay_detected"
    IMPOSSIBLE_TRAVEL = "auth.anomaly.impossible_travel"
    API_KEY_CREATED = "auth.api_key.created"
    API_KEY_REVOKED = "auth.api_key.revoked"


class SecurityEventDispatcher:
    """Manages asynchronous broadcast of security-critical events across listeners."""

    def __init__(self) -> None:
        self._listeners: Dict[str, List[EventListener]] = {}
        self._global_listeners: List[EventListener] = []
        self._event_history: List[Dict[str, Any]] = []
        self._history_limit = 1000

    def subscribe(self, event_type: str, listener: EventListener) -> None:
        """Register an async callback listener for a specific event type."""
        if event_type not in self._listeners:
            self._listeners[event_type] = []
        self._listeners[event_type].append(listener)

    def subscribe_all(self, listener: EventListener) -> None:
        """Register an async listener for all emitted events."""
        self._global_listeners.append(listener)

    def unsubscribe(self, event_type: str, listener: EventListener) -> None:
        """Remove a listener for an event type."""
        if event_type in self._listeners and listener in self._listeners[event_type]:
            self._listeners[event_type].remove(listener)

    async def dispatch(
        self,
        event_type: str,
        user_id: Optional[str] = None,
        tenant_id: Optional[str] = None,
        ip_address: Optional[str] = None,
        details: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """Broadcast an event payload to all applicable subscribers."""
        payload = {
            "event_type": event_type,
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "user_id": user_id,
            "tenant_id": tenant_id,
            "ip_address": ip_address or "unknown",
            "details": details or {},
        }

        # Save to internal ring buffer for debugging/testing
        self._event_history.append(payload)
        if len(self._event_history) > self._history_limit:
            self._event_history.pop(0)

        # Collect targets
        targets: List[EventListener] = []
        if event_type in self._listeners:
            targets.extend(self._listeners[event_type])
        targets.extend(self._global_listeners)

        if not targets:
            return payload

        # Execute listener callbacks concurrently
        tasks = [self._safe_invoke(listener, payload) for listener in targets]
        await asyncio.gather(*tasks, return_exceptions=True)

        return payload

    async def _safe_invoke(self, listener: EventListener, payload: Dict[str, Any]) -> None:
        """Safely execute subscriber callback with exception catching."""
        try:
            await listener(payload)
        except Exception as exc:
            logger.error("Error executing security event subscriber %s: %s", listener, exc)

    def get_history(self, event_type: Optional[str] = None) -> List[Dict[str, Any]]:
        """Retrieve recent dispatched events."""
        if event_type:
            return [e for e in self._event_history if e["event_type"] == event_type]
        return list(self._event_history)

    def clear_history(self) -> None:
        """Clear recorded events history."""
        self._event_history.clear()


# Global singleton
security_event_dispatcher = SecurityEventDispatcher()

