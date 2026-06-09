"""Unit tests for manager lifecycle hook bus and extension event redaction."""

from __future__ import annotations

import asyncio
from typing import cast
from uuid import uuid4

import pytest

from litestar_auth._manager.hooks import (
    ExtensionManagerHookEvent,
    ManagerHookBus,
    ManagerHookEvent,
    ManagerHookName,
    dispatch_after_login,
    redact_manager_hook_event,
    wrap_extension_manager_hook_subscriber,
)
from litestar_auth._plugin.user_manager_builder import attach_extension_manager_hook_subscribers
from litestar_auth.manager import BaseUserManager, UserManagerSecurity
from litestar_auth.password import PasswordHelper
from tests.integration.conftest import ExampleUser, InMemoryUserDatabase

pytestmark = pytest.mark.unit


def test_redact_manager_hook_event_preserves_non_token_events() -> None:
    """Non-token lifecycle events pass through unchanged."""
    user = object()
    event = ManagerHookEvent(name="after_reset_password", args=(user, "not-a-token"))
    redacted = redact_manager_hook_event(event)
    assert redacted == ExtensionManagerHookEvent(name="after_reset_password", args=(user, "not-a-token"))


def test_redact_manager_hook_event_removes_after_update_credential_fields() -> None:
    """Extension-facing update payloads omit credential material without mutating the source dict."""
    user = object()
    update_dict = {
        "email": "updated@example.com",
        "hashed_password": "secret-hash",
        "password": "plain-secret",
        "roles": ["admin"],
    }
    event = ManagerHookEvent(name="after_update", args=(user, update_dict))

    redacted = redact_manager_hook_event(event)

    assert redacted.args == (user, {"email": "updated@example.com", "roles": ["admin"]})
    assert redacted.args[1] is not update_dict
    assert update_dict == {
        "email": "updated@example.com",
        "hashed_password": "secret-hash",
        "password": "plain-secret",
        "roles": ["admin"],
    }


def test_redact_manager_hook_event_preserves_malformed_after_update_events() -> None:
    """Malformed manual update events pass through rather than failing during redaction."""
    event = ManagerHookEvent(name="after_update", args=(object(),))

    redacted = redact_manager_hook_event(event)

    assert redacted.args == event.args


def test_redact_manager_hook_event_preserves_after_update_with_non_dict_payload() -> None:
    """Manual update events with non-dict payloads pass through unchanged."""
    event = ManagerHookEvent(name="after_update", args=(object(), object()))

    redacted = redact_manager_hook_event(event)

    assert redacted.args == event.args


@pytest.mark.parametrize(
    "name",
    [
        "after_register",
        "after_forgot_password",
        "after_request_verify_token",
        "after_organization_invitation",
    ],
)
def test_redact_manager_hook_event_redacts_token_bearing_events(name: str) -> None:
    """Token-bearing lifecycle events redact the declared token argument."""
    user = object()
    event = ManagerHookEvent(name=cast("ManagerHookName", name), args=(user, "secret-token"))
    redacted = redact_manager_hook_event(event)
    assert redacted.name == name
    assert redacted.args == (user, None)


def test_redact_manager_hook_event_preserves_absent_token_value() -> None:
    """Token-bearing lifecycle events preserve ``None`` when no token was issued."""
    user = object()
    event = ManagerHookEvent(name="after_request_verify_token", args=(user, None))
    redacted = redact_manager_hook_event(event)
    assert redacted.args == (user, None)


def test_redact_manager_hook_event_preserves_missing_token_argument() -> None:
    """Token-bearing lifecycle events pass through unchanged when no token slot exists."""
    event = ManagerHookEvent(name="after_request_verify_token", args=())
    redacted = redact_manager_hook_event(event)
    assert redacted.args == ()


async def test_dispatch_after_login_ignores_objects_without_login_hook() -> None:
    """Login dispatch is a no-op for custom manager-shaped objects without a login hook."""
    await dispatch_after_login(object(), object())


async def test_wrap_extension_manager_hook_subscriber_redacts_before_dispatch() -> None:
    """Wrapped extension subscribers receive redacted event payloads."""
    received: list[ExtensionManagerHookEvent] = []

    async def record(event: ExtensionManagerHookEvent) -> None:
        await asyncio.sleep(0)
        received.append(event)

    subscriber = wrap_extension_manager_hook_subscriber(record)
    user = object()
    await subscriber(ManagerHookEvent(name="after_register", args=(user, "secret-token")))

    assert len(received) == 1
    assert received[0].name == "after_register"
    assert received[0].args == (user, None)


async def test_manager_hook_bus_redacts_extension_copy_after_internal_update_hook() -> None:
    """Internal hooks receive full update payloads while extension subscribers receive a copy."""
    internal_events: list[tuple[object, dict[str, object]]] = []
    extension_events: list[ExtensionManagerHookEvent] = []

    class HookTarget:
        async def on_after_update(self, user: object, update_dict: dict[str, object]) -> None:
            internal_events.append((user, update_dict))

    async def record(event: ExtensionManagerHookEvent) -> None:
        await asyncio.sleep(0)
        extension_events.append(event)

    user = object()
    update_dict: dict[str, object] = {
        "email": "updated@example.com",
        "hashed_password": "secret-hash",
        "is_verified": True,
    }
    bus = ManagerHookBus[object](HookTarget())
    bus.subscribe(wrap_extension_manager_hook_subscriber(record))

    await bus.fire("after_update", user, update_dict)

    assert internal_events == [(user, update_dict)]
    assert extension_events == [
        ExtensionManagerHookEvent(
            name="after_update",
            args=(user, {"email": "updated@example.com", "is_verified": True}),
        ),
    ]
    assert extension_events[0].args[1] is not update_dict
    assert update_dict["hashed_password"] == "secret-hash"


async def test_attach_extension_manager_hook_subscribers_subscribes_once_per_manager() -> None:
    """Extension subscribers attach to one manager instance without duplicate wiring."""
    password_helper = PasswordHelper()
    user_db = InMemoryUserDatabase([])
    manager = BaseUserManager(
        user_db,
        password_helper=password_helper,
        security=UserManagerSecurity(
            verification_token_secret="0123456789abcdef" * 4,
            reset_password_token_secret="fedcba9876543210" * 4,
        ),
    )
    received: list[ExtensionManagerHookEvent] = []

    async def record(event: ExtensionManagerHookEvent) -> None:
        await asyncio.sleep(0)
        received.append(event)

    attach_extension_manager_hook_subscribers(manager, (record,))
    user = ExampleUser(
        id=uuid4(),
        email="hook@example.com",
        hashed_password=password_helper.hash("password"),
        is_verified=True,
    )
    await manager.hook_bus.fire("after_login", user)

    assert len(received) == 1
    assert received[0].name == "after_login"
    assert received[0].args == (user,)
