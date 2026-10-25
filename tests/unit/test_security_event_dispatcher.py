"""Unit tests for asynchronous security event dispatcher."""

import asyncio
import pytest
from auth_service.services.security_event_dispatcher import (
    SecurityEventDispatcher,
    SecurityEventType,
)


@pytest.mark.asyncio
async def test_dispatch_and_subscription():
    dispatcher = SecurityEventDispatcher()
    received_events = []

    async def on_login_failure(event):
        received_events.append(event)

    dispatcher.subscribe(SecurityEventType.LOGIN_FAILED, on_login_failure)

    await dispatcher.dispatch(
        event_type=SecurityEventType.LOGIN_FAILED,
        user_id="user-123",
        tenant_id="tenant-alpha",
        ip_address="192.168.1.100",
        details={"reason": "invalid_password"},
    )

    assert len(received_events) == 1
    ev = received_events[0]
    assert ev["event_type"] == SecurityEventType.LOGIN_FAILED
    assert ev["user_id"] == "user-123"
    assert ev["details"]["reason"] == "invalid_password"


@pytest.mark.asyncio
async def test_global_subscriber():
    dispatcher = SecurityEventDispatcher()
    all_events = []

    async def on_any_event(event):
        all_events.append(event)

    dispatcher.subscribe_all(on_any_event)

    await dispatcher.dispatch(event_type=SecurityEventType.ACCOUNT_LOCKED, user_id="u1")
    await dispatcher.dispatch(event_type=SecurityEventType.PASSWORD_CHANGED, user_id="u2")

    assert len(all_events) == 2


@pytest.mark.asyncio
async def test_unsubscribe():
    dispatcher = SecurityEventDispatcher()
    counter = {"count": 0}

    async def listener(event):
        counter["count"] += 1

    dispatcher.subscribe(SecurityEventType.TOKEN_REVOKED, listener)
    await dispatcher.dispatch(SecurityEventType.TOKEN_REVOKED)
    assert counter["count"] == 1

    dispatcher.unsubscribe(SecurityEventType.TOKEN_REVOKED, listener)
    await dispatcher.dispatch(SecurityEventType.TOKEN_REVOKED)
    assert counter["count"] == 1


@pytest.mark.asyncio
async def test_history_buffer():
    dispatcher = SecurityEventDispatcher()
    await dispatcher.dispatch(SecurityEventType.IMPOSSIBLE_TRAVEL, user_id="u10")
    await dispatcher.dispatch(SecurityEventType.API_KEY_CREATED, user_id="u10")

    history = dispatcher.get_history()
    assert len(history) == 2

    travel_history = dispatcher.get_history(event_type=SecurityEventType.IMPOSSIBLE_TRAVEL)
    assert len(travel_history) == 1

    dispatcher.clear_history()
    assert len(dispatcher.get_history()) == 0
