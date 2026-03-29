"""Tests for authentication backend composition."""

from __future__ import annotations

import importlib
from typing import TYPE_CHECKING, Any, cast
from unittest.mock import AsyncMock, Mock
from uuid import UUID, uuid4

import pytest
from litestar.connection import ASGIConnection
from litestar.enums import MediaType
from litestar.exceptions import NotAuthorizedException
from litestar.response import Response

from litestar_auth.authentication import backend as backend_module
from litestar_auth.authentication.backend import AuthenticationBackend, _bind_strategy_session
from litestar_auth.authentication.strategy.base import SessionBindable
from litestar_auth.authentication.transport.cookie import CookieTransport
from tests._helpers import ExampleUser

if TYPE_CHECKING:
    from types import ModuleType

    from litestar.types import HTTPScope

pytestmark = pytest.mark.unit


def _backend_module() -> ModuleType:
    """Import the backend module lazily so coverage records module execution.

    Returns:
        The runtime backend module object.
    """
    return importlib.import_module("litestar_auth.authentication.backend")


def _build_connection() -> ASGIConnection[Any, Any, Any, Any]:
    """Create a minimal HTTP connection for backend authentication tests.

    Returns:
        Minimal Litestar connection object.
    """
    scope = {
        "type": "http",
        "headers": [],
        "path_params": {},
        "query_string": b"",
    }
    return ASGIConnection(scope=cast("HTTPScope", scope))


def test_backend_module_executes_under_coverage() -> None:
    """Reload the backend module in-test so coverage records class and helper definitions."""
    reloaded_module = importlib.reload(backend_module)

    assert reloaded_module.AuthenticationBackend is _backend_module().AuthenticationBackend
    assert reloaded_module._bind_strategy_session is not None
    assert reloaded_module._invalidate_refresh_artifacts is not None


async def test_backend_login_composes_strategy_and_transport() -> None:
    """Login issues a token via strategy and hands it to the transport."""
    user = ExampleUser(id=uuid4())
    transport = Mock()
    transport.read_token = AsyncMock()
    strategy = AsyncMock()
    backend = AuthenticationBackend[ExampleUser, UUID](
        name="jwt-bearer",
        transport=transport,
        strategy=strategy,
    )
    response = Response(content={"ok": True}, media_type=MediaType.JSON)
    strategy.write_token.return_value = "issued-token"
    transport.set_login_token.return_value = response

    result = await backend.login(user)

    assert result is response
    assert backend.name == "jwt-bearer"
    strategy.write_token.assert_awaited_once_with(user)
    transport.set_login_token.assert_called_once()
    called_response, called_token = transport.set_login_token.call_args.args
    assert isinstance(called_response, Response)
    assert called_response.content is None
    assert called_token == "issued-token"


async def test_backend_logout_composes_strategy_and_transport() -> None:
    """Logout destroys the token before clearing transport state."""
    user = ExampleUser(id=uuid4())
    transport = Mock()
    transport.read_token = AsyncMock()
    strategy = AsyncMock()
    backend = AuthenticationBackend[ExampleUser, UUID](
        name="cookie-db",
        transport=transport,
        strategy=cast("Any", strategy),
    )
    response = Response(content=None)
    transport.set_logout.return_value = response

    result = await backend.logout(user, "token-1")

    assert result is response
    strategy.destroy_token.assert_awaited_once_with("token-1", user)
    transport.set_logout.assert_called_once()
    called_response = transport.set_logout.call_args.args[0]
    assert isinstance(called_response, Response)
    assert called_response.content is None


async def test_backend_logout_does_not_read_transport_token() -> None:
    """Backend logout consumes the provided token and never reads transport state."""
    user = ExampleUser(id=uuid4())
    transport = Mock()
    transport.read_token = AsyncMock()
    strategy = AsyncMock()
    backend = AuthenticationBackend[ExampleUser, UUID](
        name="cookie-db",
        transport=transport,
        strategy=cast("Any", strategy),
    )

    await backend.logout(user, "token-from-controller")

    strategy.destroy_token.assert_awaited_once_with("token-from-controller", user)
    transport.read_token.assert_not_called()
    transport.set_logout.assert_called_once()


async def test_terminate_session_reads_transport_token_then_delegates_to_logout() -> None:
    """Session termination revokes refresh artifacts before logout invalidation+cleanup."""
    user = ExampleUser(id=uuid4())
    connection = _build_connection()
    transport = Mock()
    transport.read_token = AsyncMock(return_value="authenticate-token")
    transport.read_logout_token = AsyncMock(return_value="logout-token")

    class StrategyWithRevocation:
        def __init__(self) -> None:
            self.read_token = AsyncMock()
            self.write_token = AsyncMock()
            self.destroy_token = AsyncMock()
            self.invalidate_all_tokens = AsyncMock()

    strategy = StrategyWithRevocation()
    expected_response = Response(content=None)
    transport.set_logout.return_value = expected_response
    backend = AuthenticationBackend[ExampleUser, UUID](
        name="cookie-db",
        transport=transport,
        strategy=cast("Any", strategy),
    )

    response = await backend.terminate_session(connection, user)

    assert response is expected_response
    transport.read_logout_token.assert_awaited_once_with(connection)
    transport.read_token.assert_not_called()
    strategy.invalidate_all_tokens.assert_awaited_once_with(user)
    strategy.destroy_token.assert_awaited_once_with("logout-token", user)
    transport.set_logout.assert_called_once()
    assert strategy.destroy_token.await_count == 1
    assert strategy.invalidate_all_tokens.await_count == 1


async def test_terminate_session_falls_back_to_read_token_without_logout_reader() -> None:
    """Session termination uses read_token when the transport lacks read_logout_token."""
    user = ExampleUser(id=uuid4())
    connection = _build_connection()
    transport = Mock()
    transport.read_token = AsyncMock(return_value="authenticate-token")

    class StrategyWithRevocation:
        def __init__(self) -> None:
            self.read_token = AsyncMock()
            self.write_token = AsyncMock()
            self.destroy_token = AsyncMock()
            self.invalidate_all_tokens = AsyncMock()

    strategy = StrategyWithRevocation()
    expected_response = Response(content=None)
    transport.set_logout.return_value = expected_response
    backend = AuthenticationBackend[ExampleUser, UUID](
        name="bearer-db",
        transport=transport,
        strategy=cast("Any", strategy),
    )

    response = await backend.terminate_session(connection, user)

    assert response is expected_response
    transport.read_token.assert_awaited_once_with(connection)
    strategy.invalidate_all_tokens.assert_awaited_once_with(user)
    strategy.destroy_token.assert_awaited_once_with("authenticate-token", user)
    transport.set_logout.assert_called_once()


async def test_terminate_session_skips_refresh_invalidation_when_strategy_lacks_protocol() -> None:
    """Session termination only revokes all artifacts for protocol-matching strategies."""
    user = ExampleUser(id=uuid4())
    connection = _build_connection()
    transport = Mock()
    transport.read_token = AsyncMock(return_value="authenticate-token")

    class StrategyWithoutRevocation:
        def __init__(self) -> None:
            self.read_token = AsyncMock()
            self.write_token = AsyncMock()
            self.destroy_token = AsyncMock()

    strategy = StrategyWithoutRevocation()
    expected_response = Response(content=None)
    transport.set_logout.return_value = expected_response
    backend = AuthenticationBackend[ExampleUser, UUID](
        name="bearer-db",
        transport=transport,
        strategy=cast("Any", strategy),
    )

    response = await backend.terminate_session(connection, user)

    assert response is expected_response
    transport.read_token.assert_awaited_once_with(connection)
    strategy.destroy_token.assert_awaited_once_with("authenticate-token", user)
    transport.set_logout.assert_called_once()


async def test_backend_authenticate_reads_transport_token_and_resolves_user() -> None:
    """Authenticate reads the transport token before asking the strategy."""
    user = ExampleUser(id=uuid4())
    connection = _build_connection()
    user_manager = AsyncMock()
    transport = Mock()
    transport.read_token = AsyncMock()
    strategy = AsyncMock()
    backend = AuthenticationBackend[ExampleUser, UUID](
        name="redis-cookie",
        transport=transport,
        strategy=strategy,
    )
    transport.read_token.return_value = "token-2"
    strategy.read_token.return_value = user

    result = await backend.authenticate(connection, user_manager)

    assert result == user
    transport.read_token.assert_awaited_once_with(connection)
    strategy.read_token.assert_awaited_once_with("token-2", user_manager)


def test_backend_with_session_rebinds_strategy_when_supported() -> None:
    """with_session returns a new backend instance when the strategy supports rebinding."""
    transport = Mock()
    session = Mock()
    rebound_strategy = object()

    class StrategyWithSession:
        def __init__(self) -> None:
            self.with_session = Mock(return_value=rebound_strategy)

        async def read_token(self, token: str | None, user_manager: object) -> object:
            del token, user_manager
            return None

        async def write_token(self, user: object) -> str:
            del user
            return "token"

        async def destroy_token(self, token: str, user: object) -> None:
            del token, user

    original_strategy = StrategyWithSession()
    backend = AuthenticationBackend[ExampleUser, UUID](
        name="with-session-backend",
        transport=transport,
        strategy=cast("Any", original_strategy),
    )

    rebound_backend = backend.with_session(session)

    assert rebound_backend is not backend
    assert isinstance(rebound_backend, AuthenticationBackend)
    assert rebound_backend.name == backend.name
    assert rebound_backend.transport is backend.transport
    assert rebound_backend.strategy is rebound_strategy
    original_strategy.with_session.assert_called_once_with(session)


def test_backend_with_session_returns_self_for_non_bindable_strategy() -> None:
    """with_session returns the existing backend when the strategy is not session-bindable."""

    class StrategyWithoutSession:
        async def read_token(self, token: str | None, user_manager: object) -> object:
            del token, user_manager
            return None

        async def write_token(self, user: object) -> str:
            del user
            return "token"

        async def destroy_token(self, token: str, user: object) -> None:
            del token, user

    strategy = StrategyWithoutSession()
    backend = AuthenticationBackend[ExampleUser, UUID](
        name="plain-backend",
        transport=Mock(),
        strategy=cast("Any", strategy),
    )

    assert backend.with_session(Mock()) is backend


def test_bind_strategy_session_uses_with_session_when_callable() -> None:
    """_bind_strategy_session delegates to strategy.with_session when available."""
    session = Mock()
    sentinel_strategy = object()

    class StrategyWithSession:
        def __init__(self) -> None:
            self.with_session = Mock(return_value=sentinel_strategy)

        async def read_token(self, token: str | None, user_manager: object) -> object:
            del token, user_manager
            return None

        async def write_token(self, user: object) -> str:
            del user
            return "token"

        async def destroy_token(self, token: str, user: object) -> None:
            del token, user

    strategy = StrategyWithSession()

    result = _bind_strategy_session(cast("Any", strategy), session)

    assert result is sentinel_strategy
    strategy.with_session.assert_called_once_with(session)


def test_bind_strategy_session_leaves_non_bindable_strategy_unchanged() -> None:
    """_bind_strategy_session returns the original strategy when it is not SessionBindable."""

    class StrategyWithoutSession:
        async def read_token(self, token: str | None, user_manager: object) -> object:
            del token, user_manager
            return None

        async def write_token(self, user: object) -> str:
            del user
            return "token"

        async def destroy_token(self, token: str, user: object) -> None:
            del token, user

    strategy = StrategyWithoutSession()

    result = _bind_strategy_session(cast("Any", strategy), Mock())

    assert result is strategy
    assert not isinstance(strategy, SessionBindable)


async def test_backend_logout_clears_refresh_cookie_for_cookie_transport() -> None:
    """Backend logout expires both access and refresh cookies for CookieTransport."""
    user = ExampleUser(id=uuid4())
    transport = CookieTransport(cookie_name="auth", secure=False)
    strategy = AsyncMock()
    backend = AuthenticationBackend[ExampleUser, UUID](
        name="cookie-backend",
        transport=transport,
        strategy=cast("Any", strategy),
    )

    response = await backend.logout(user, "token-1")

    strategy.destroy_token.assert_awaited_once_with("token-1", user)
    cookie_keys = [cookie.key for cookie in response.cookies]
    assert "auth" in cookie_keys
    assert "auth_refresh" in cookie_keys
    refresh_cookie = next(c for c in response.cookies if c.key == "auth_refresh")
    assert refresh_cookie.max_age == 0
    assert not refresh_cookie.value


async def test_backend_logout_skips_refresh_cookie_for_non_cookie_transport() -> None:
    """Backend logout does not attempt refresh-cookie clearing for non-cookie transports."""
    user = ExampleUser(id=uuid4())
    transport = Mock()
    transport.read_token = AsyncMock()
    strategy = AsyncMock()
    backend = AuthenticationBackend[ExampleUser, UUID](
        name="bearer-backend",
        transport=transport,
        strategy=cast("Any", strategy),
    )
    response = Response(content=None)
    transport.set_logout.return_value = response

    result = await backend.logout(user, "token-1")

    assert result is response
    strategy.destroy_token.assert_awaited_once_with("token-1", user)
    transport.set_logout.assert_called_once()
    assert not hasattr(transport, "clear_refresh_token") or not transport.clear_refresh_token.called


async def test_terminate_session_raises_when_transport_has_no_current_token() -> None:
    """Session termination rejects connections without a logout token."""
    user = ExampleUser(id=uuid4())
    connection = _build_connection()
    transport = Mock()
    transport.read_token = AsyncMock(return_value=None)
    strategy = AsyncMock()
    backend = AuthenticationBackend[ExampleUser, UUID](
        name="bearer-backend",
        transport=transport,
        strategy=cast("Any", strategy),
    )

    with pytest.raises(NotAuthorizedException, match=r"Authentication credentials were not provided\."):
        await backend.terminate_session(connection, user)

    strategy.invalidate_all_tokens.assert_not_called()
    strategy.destroy_token.assert_not_called()
    transport.set_logout.assert_not_called()


async def test_invalidate_refresh_artifacts_is_noop_for_non_capable_strategy() -> None:
    """Refresh invalidation helper skips strategies without bulk-invalidation support."""

    class StrategyWithoutRefreshInvalidation:
        async def read_token(self, token: str | None, user_manager: object) -> object:
            del token, user_manager
            return None

        async def write_token(self, user: object) -> str:
            del user
            return "token"

        async def destroy_token(self, token: str, user: object) -> None:
            del token, user

    strategy = StrategyWithoutRefreshInvalidation()
    user = ExampleUser(id=uuid4())

    await _backend_module()._invalidate_refresh_artifacts(cast("Any", strategy), user)
