"""Tests for the Litestar authentication middleware."""

from __future__ import annotations

import asyncio
import importlib
import logging
from functools import partial
from typing import TYPE_CHECKING, Any, Self, cast
from unittest.mock import AsyncMock, MagicMock, Mock
from uuid import UUID, uuid4

import pytest
from litestar.connection import ASGIConnection
from litestar.datastructures.state import State

import litestar_auth.authentication.middleware as middleware_module
from litestar_auth._plugin.scoped_session import get_or_create_scoped_session
from litestar_auth.authentication.middleware import (
    LitestarAuthMiddleware,
    _cookie_header_contains_any_cookie_name,
    _request_supplied_auth_credentials,
)
from litestar_auth.authentication.middleware import logger as middleware_logger
from tests._helpers import ExampleUser

if TYPE_CHECKING:
    from types import TracebackType

    from litestar.types import HTTPReceiveMessage, HTTPScope, HTTPSendMessage, Receive, Scope, Send

pytestmark = pytest.mark.unit


class DummySession:
    """Minimal session object used by middleware tests (mirrors ``AsyncSession`` surface)."""

    async def __aenter__(self) -> Self:
        """Enter async context.

        Returns:
            This session instance.
        """
        return self

    async def __aexit__(
        self,
        exc_type: type[BaseException] | None,
        exc: BaseException | None,
        traceback: TracebackType | None,
    ) -> None:
        """Exit async context (no-op)."""
        del exc_type, exc, traceback

    async def close(self) -> None:
        """No-op for lifecycle parity."""

    async def commit(self) -> None:
        """No-op commit for lifecycle parity."""

    async def rollback(self) -> None:
        """No-op rollback for lifecycle parity."""


class DummySessionMaker:
    """Callable session factory returning a dummy session (mirrors ``async_sessionmaker()``)."""

    def __init__(self, session: DummySession) -> None:
        """Store the dummy session and track calls."""
        self.session = session
        self.call_count = 0

    def __call__(self) -> DummySession:
        """Return the dummy session (one logical session per factory call for this test double).

        Returns:
            The shared dummy session.
        """
        self.call_count += 1
        return self.session


class DummyRouteHandler:
    """Minimal route handler exposing the opt mapping Litestar expects."""

    def __init__(self) -> None:
        """Initialize route options."""
        self.opt: dict[str, object] = {}


def _build_scope() -> HTTPScope:
    """Create a minimal HTTP scope for middleware tests.

    Returns:
        Minimal HTTP scope.
    """
    litestar_app = MagicMock()
    litestar_app.state = State()
    return cast(
        "HTTPScope",
        {
            "type": "http",
            "asgi": {"version": "3.0", "spec_version": "2.3"},
            "http_version": "1.1",
            "method": "GET",
            "scheme": "http",
            "path": "/protected",
            "raw_path": b"/protected",
            "root_path": "",
            "query_string": b"",
            "headers": [],
            "client": ("127.0.0.1", 12345),
            "server": ("testserver", 80),
            "path_params": {},
            "route_handler": DummyRouteHandler(),
            "litestar_app": litestar_app,
        },
    )


def _build_connection(scope: HTTPScope) -> ASGIConnection[Any, Any, Any, Any]:
    """Create an ASGI connection for the provided scope.

    Args:
        scope: HTTP scope backing the connection.

    Returns:
        Litestar ASGI connection.
    """
    return ASGIConnection(scope)


async def _receive() -> HTTPReceiveMessage:
    """Return an empty ASGI message.

    Returns:
        Empty ASGI message.
    """
    await asyncio.sleep(0)
    return {"type": "http.request", "body": b"", "more_body": False}


async def _send(_: HTTPSendMessage) -> None:
    """Consume ASGI messages emitted by the wrapped app."""
    await asyncio.sleep(0)


async def _app(scope: Scope, receive: Receive, send: Send) -> None:
    """No-op ASGI app used by the middleware under test."""
    del scope
    del receive
    del send
    await asyncio.sleep(0)


async def test_middleware_sets_authenticated_user_in_scope() -> None:
    """Middleware authenticates through the request-local authenticator."""
    scope = _build_scope()
    session = DummySession()
    session_maker = DummySessionMaker(session)
    user = ExampleUser(id=uuid4())
    authenticator = Mock()
    authenticator.authenticate = AsyncMock(return_value=(user, "bearer-jwt"))
    authenticator_factory = Mock(return_value=authenticator)
    middleware = LitestarAuthMiddleware[ExampleUser, UUID](
        app=_app,
        get_request_session=partial(get_or_create_scoped_session, session_maker=cast("Any", session_maker)),
        authenticator_factory=authenticator_factory,
    )

    await middleware(scope, cast("Receive", _receive), cast("Send", _send))

    assert scope["user"] == user
    assert scope["auth"] == "bearer-jwt"
    assert session_maker.call_count == 1
    authenticator_factory.assert_called_once_with(session)
    authenticator.authenticate.assert_awaited_once()
    await_args = authenticator.authenticate.await_args
    assert await_args is not None
    connection = cast("ASGIConnection[Any, Any, Any, Any]", await_args.args[0])
    assert connection.scope is scope


async def test_authenticate_request_reuses_scoped_session_and_returns_resolved_user() -> None:
    """authenticate_request reuses an existing scoped session and returns the resolved user."""
    scope = _build_scope()
    bound_session = DummySession()
    cast("dict[str, Any]", scope)["_aa_connection_state"] = {"_sqlalchemy_db_session": bound_session}
    session_maker = DummySessionMaker(DummySession())
    user = ExampleUser(id=uuid4())
    authenticator = Mock()
    authenticator.authenticate = AsyncMock(return_value=(user, "bearer-jwt"))
    authenticator_factory = Mock(return_value=authenticator)
    middleware = LitestarAuthMiddleware[ExampleUser, UUID](
        app=_app,
        get_request_session=partial(get_or_create_scoped_session, session_maker=cast("Any", session_maker)),
        authenticator_factory=authenticator_factory,
    )

    result = await middleware.authenticate_request(_build_connection(scope))

    assert result.user == user
    assert result.auth == "bearer-jwt"
    assert session_maker.call_count == 0
    authenticator_factory.assert_called_once_with(bound_session)
    authenticator.authenticate.assert_awaited_once()


async def test_middleware_leaves_unauthenticated_requests_as_none() -> None:
    """Middleware returns ``None`` user/auth instead of raising 401."""
    scope = _build_scope()
    session = DummySession()
    session_maker = DummySessionMaker(session)
    authenticator = Mock()
    authenticator.authenticate = AsyncMock(return_value=(None, None))
    middleware = LitestarAuthMiddleware[ExampleUser, UUID](
        app=_app,
        get_request_session=partial(get_or_create_scoped_session, session_maker=cast("Any", session_maker)),
        authenticator_factory=Mock(return_value=authenticator),
    )

    await middleware(scope, cast("Receive", _receive), cast("Send", _send))

    assert scope["user"] is None
    assert scope["auth"] is None
    assert session_maker.call_count == 1
    authenticator.authenticate.assert_awaited_once()


async def test_authenticate_request_propagates_authenticator_factory_errors() -> None:
    """authenticate_request propagates factory failures without swallowing them."""
    scope = _build_scope()
    session = DummySession()
    session_maker = DummySessionMaker(session)
    expected = RuntimeError("factory boom")
    authenticator_factory = Mock(side_effect=expected)
    middleware = LitestarAuthMiddleware[ExampleUser, UUID](
        app=_app,
        get_request_session=partial(get_or_create_scoped_session, session_maker=cast("Any", session_maker)),
        authenticator_factory=authenticator_factory,
    )

    with pytest.raises(RuntimeError, match="factory boom"):
        await middleware.authenticate_request(_build_connection(scope))

    assert session_maker.call_count == 1
    authenticator_factory.assert_called_once_with(session)


async def test_middleware_logs_failed_token_validation_when_credentials_present(
    caplog: pytest.LogCaptureFixture,
) -> None:
    """Requests carrying credentials but resolving no user are logged as token failures."""
    scope = _build_scope()
    scope["headers"] = [(b"authorization", b"Bearer invalid-token")]
    session = DummySession()
    session_maker = DummySessionMaker(session)
    authenticator = Mock()
    authenticator.authenticate = AsyncMock(return_value=(None, None))
    middleware = LitestarAuthMiddleware[ExampleUser, UUID](
        app=_app,
        get_request_session=partial(get_or_create_scoped_session, session_maker=cast("Any", session_maker)),
        authenticator_factory=Mock(return_value=authenticator),
    )

    with caplog.at_level(logging.WARNING, logger=middleware_logger.name):
        await middleware(scope, cast("Receive", _receive), cast("Send", _send))

    events = [cast("str | None", getattr(record, "event", None)) for record in caplog.records]
    assert events == ["token_validation_failed"]


async def test_authenticate_request_does_not_log_failed_token_validation_when_user_resolves(
    caplog: pytest.LogCaptureFixture,
) -> None:
    """Resolved users suppress token failure logging even when credentials are present."""
    scope = _build_scope()
    scope["headers"] = [(b"authorization", b"Bearer valid-token")]
    session = DummySession()
    session_maker = DummySessionMaker(session)
    user = ExampleUser(id=uuid4())
    authenticator = Mock()
    authenticator.authenticate = AsyncMock(return_value=(user, "bearer-jwt"))
    middleware = LitestarAuthMiddleware[ExampleUser, UUID](
        app=_app,
        get_request_session=partial(get_or_create_scoped_session, session_maker=cast("Any", session_maker)),
        authenticator_factory=Mock(return_value=authenticator),
    )

    with caplog.at_level(logging.WARNING, logger=middleware_logger.name):
        result = await middleware.authenticate_request(_build_connection(scope))

    assert result.user == user
    assert result.auth == "bearer-jwt"
    assert not caplog.records


async def test_middleware_does_not_log_failed_token_validation_for_unrelated_cookies(
    caplog: pytest.LogCaptureFixture,
) -> None:
    """Cookies unrelated to auth do not trigger token validation failure logging."""
    scope = _build_scope()
    scope["headers"] = [(b"cookie", b"sessionid=abc123")]
    session = DummySession()
    session_maker = DummySessionMaker(session)
    authenticator = Mock()
    authenticator.authenticate = AsyncMock(return_value=(None, None))
    middleware = LitestarAuthMiddleware[ExampleUser, UUID](
        app=_app,
        get_request_session=partial(get_or_create_scoped_session, session_maker=cast("Any", session_maker)),
        authenticator_factory=Mock(return_value=authenticator),
        auth_cookie_names=frozenset({b"litestar_auth", b"litestar_auth_refresh"}),
    )

    with caplog.at_level(logging.WARNING, logger=middleware_logger.name):
        await middleware(scope, cast("Receive", _receive), cast("Send", _send))

    events = [cast("str | None", getattr(record, "event", None)) for record in caplog.records]
    assert events == []


async def test_middleware_logs_failed_token_validation_for_configured_auth_cookies(
    caplog: pytest.LogCaptureFixture,
) -> None:
    """Requests carrying configured auth cookies but resolving no user are logged as token failures."""
    scope = _build_scope()
    scope["headers"] = [(b"cookie", b"litestar_auth=invalid-token")]
    session = DummySession()
    session_maker = DummySessionMaker(session)
    authenticator = Mock()
    authenticator.authenticate = AsyncMock(return_value=(None, None))
    middleware = LitestarAuthMiddleware[ExampleUser, UUID](
        app=_app,
        get_request_session=partial(get_or_create_scoped_session, session_maker=cast("Any", session_maker)),
        authenticator_factory=Mock(return_value=authenticator),
        auth_cookie_names=frozenset({b"litestar_auth", b"litestar_auth_refresh"}),
    )

    with caplog.at_level(logging.WARNING, logger=middleware_logger.name):
        await middleware(scope, cast("Receive", _receive), cast("Send", _send))

    events = [cast("str | None", getattr(record, "event", None)) for record in caplog.records]
    assert events == ["token_validation_failed"]


def test_request_supplied_auth_credentials_detects_bearer_header() -> None:
    """Authorization headers count as supplied auth credentials."""
    scope = _build_scope()
    scope["headers"] = [(b"authorization", b"Bearer token")]

    has_credentials = _request_supplied_auth_credentials(
        _build_connection(scope),
        auth_cookie_names=frozenset({b"litestar_auth"}),
    )

    assert has_credentials is True


def test_request_supplied_auth_credentials_detects_configured_auth_cookie() -> None:
    """Configured auth cookies count as supplied auth credentials."""
    scope = _build_scope()
    scope["headers"] = [(b"cookie", b"other=value; litestar_auth=token; another=1")]

    has_credentials = _request_supplied_auth_credentials(
        _build_connection(scope),
        auth_cookie_names=frozenset({b"litestar_auth", b"litestar_auth_refresh"}),
    )

    assert has_credentials is True


def test_request_supplied_auth_credentials_returns_false_without_matching_headers() -> None:
    """Missing auth headers and unrelated cookies do not count as supplied credentials."""
    scope = _build_scope()
    scope["headers"] = [(b"x-test", b"value"), (b"cookie", b"sessionid=abc123")]

    has_credentials = _request_supplied_auth_credentials(
        _build_connection(scope),
        auth_cookie_names=frozenset({b"litestar_auth"}),
    )

    assert has_credentials is False


def test_cookie_header_contains_any_cookie_name_strips_whitespace() -> None:
    """Cookie-name matching tolerates header whitespace and multiple cookie pairs."""
    assert _cookie_header_contains_any_cookie_name(
        b"sessionid=abc123; litestar_auth_refresh=token; theme=dark",
        frozenset({b"litestar_auth", b"litestar_auth_refresh"}),
    )
    assert not _cookie_header_contains_any_cookie_name(
        b"sessionid=abc123; theme=dark",
        frozenset({b"litestar_auth", b"litestar_auth_refresh"}),
    )


def test_middleware_module_reload_preserves_public_behavior() -> None:
    """Reloading the module preserves helper behavior while covering import-time definitions."""
    reloaded_module = importlib.reload(middleware_module)

    assert reloaded_module._cookie_header_contains_any_cookie_name(
        b"litestar_auth=token",
        frozenset({b"litestar_auth"}),
    )
