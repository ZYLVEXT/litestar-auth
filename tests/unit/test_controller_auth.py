"""Unit tests for auth controller helpers and error paths."""

from __future__ import annotations

import importlib
from datetime import timedelta
from types import CellType, FunctionType
from typing import Any, cast
from unittest.mock import AsyncMock, MagicMock
from uuid import UUID, uuid4

import pytest
from litestar.enums import MediaType
from litestar.exceptions import ClientException, NotAuthorizedException
from litestar.response import Response

import litestar_auth.controllers.auth as auth_controller_module
from litestar_auth._plugin.config import DEFAULT_USER_MANAGER_DEPENDENCY_KEY
from litestar_auth.authentication.backend import AuthenticationBackend
from litestar_auth.authentication.strategy.base import Strategy, UserManagerProtocol
from litestar_auth.authentication.transport.bearer import BearerTransport
from litestar_auth.authentication.transport.cookie import CookieTransport
from litestar_auth.controllers.auth import (
    _LOGIN_EMAIL_MAX_LENGTH,
    _LOGIN_USERNAME_MAX_LENGTH,
    LoginCredentials,
    _attach_refresh_token,
    _get_refresh_strategy,
    _make_auth_controller_context,
    _resolve_login_identifier,
    create_auth_controller,
)
from litestar_auth.exceptions import ConfigurationError, ErrorCode, InactiveUserError
from litestar_auth.guards import is_authenticated

pytestmark = pytest.mark.unit

HTTP_ACCEPTED = 202
HTTP_BAD_REQUEST = 400
STATUS_UNPROCESSABLE_ENTITY = 422


def test_auth_controller_module_reload_executes_module_body() -> None:
    """Reload the auth controller module so coverage records its module-level definitions."""
    reloaded = importlib.reload(auth_controller_module)

    assert reloaded.LoginCredentials is not None
    assert reloaded.RefreshTokenRequest is not None
    assert reloaded.TOTP_PENDING_AUDIENCE == auth_controller_module.TOTP_PENDING_AUDIENCE


def test_get_refresh_strategy_raises_when_strategy_not_refreshable() -> None:
    """Passing a non-RefreshableStrategy raises ConfigurationError."""

    class PlainStrategy(Strategy):
        async def read_token(self, token: str | None, user_manager: UserManagerProtocol) -> None:
            return None

        async def write_token(self, user: object) -> str:
            return ""

        async def destroy_token(self, token: str, user: object) -> None:
            return None

    with pytest.raises(ConfigurationError) as exc_info:
        _get_refresh_strategy(PlainStrategy())

    assert "enable_refresh=True requires a strategy with refresh-token support" in str(exc_info.value)


def test_attach_refresh_token_without_cookie_sets_json_body() -> None:
    """When cookie_transport is None, refresh_token is added to response content and media_type is JSON."""
    response = Response(content={"access_token": "at"}, media_type=MediaType.JSON)
    out = _attach_refresh_token(response, "rt", cookie_transport=None)

    assert out is response
    assert out.content == {"access_token": "at", "refresh_token": "rt"}
    assert out.media_type == MediaType.JSON


def test_attach_refresh_token_with_cookie_sets_cookie() -> None:
    """When cookie_transport is set, body is unchanged and same response is returned (cookie path taken)."""
    response = Response(content={"access_token": "at"}, media_type=MediaType.JSON)
    transport = CookieTransport(cookie_name="auth", path="/auth")
    out = _attach_refresh_token(response, "rt", cookie_transport=transport)

    assert out is response
    assert out.content == {"access_token": "at"}


def test_attach_refresh_token_with_non_mapping_content_replaces_payload() -> None:
    """Non-mapping response bodies are replaced with a JSON payload containing the refresh token."""
    response = Response(content=None, media_type=MediaType.TEXT)

    out = _attach_refresh_token(response, "rt", cookie_transport=None)

    assert out is response
    assert out.content == {"refresh_token": "rt"}
    assert out.media_type == MediaType.JSON


def test_logout_guard_raises_not_authorized_when_no_credentials() -> None:
    """Guard protecting logout raises NotAuthorizedException when connection.user is None."""
    connection = MagicMock()
    connection.user = None
    handler = MagicMock()

    with pytest.raises(NotAuthorizedException) as exc_info:
        is_authenticated(connection, handler)

    assert "credentials" in exc_info.value.detail.lower() or "authorized" in exc_info.value.detail.lower()


async def test_logout_raises_not_authorized_when_user_is_none() -> None:
    """Logout handler raises NotAuthorizedException when request.user is None (defensive path)."""
    transport = BearerTransport()
    strategy = _make_minimal_strategy()

    backend = AuthenticationBackend(name="test", transport=transport, strategy=cast("Any", strategy))
    controller_class = create_auth_controller(
        backend=backend,
    )
    controller = cast("Any", controller_class(owner=MagicMock()))

    request = MagicMock()
    request.user = None
    request.headers = MagicMock()
    request.headers.get.return_value = None

    logout_handler = controller.logout.fn
    with pytest.raises(NotAuthorizedException) as exc_info:
        await logout_handler(controller, request)

    assert "credentials" in exc_info.value.detail.lower() or "authorized" in exc_info.value.detail.lower()


async def test_logout_raises_not_authorized_when_transport_returns_no_token() -> None:
    """Logout handler raises NotAuthorizedException when transport.read_token returns None."""
    transport = _TransportReturningNone()
    strategy = _make_minimal_strategy()

    backend = AuthenticationBackend(name="test", transport=transport, strategy=cast("Any", strategy))
    controller_class = create_auth_controller(
        backend=backend,
    )
    controller = cast("Any", controller_class(owner=MagicMock()))

    request = MagicMock()
    request.user = _MinimalUser()

    logout_handler = controller.logout.fn
    with pytest.raises(NotAuthorizedException) as exc_info:
        await logout_handler(controller, request)

    assert "credentials" in exc_info.value.detail.lower() or "authorized" in exc_info.value.detail.lower()


async def test_logout_delegates_session_termination_to_backend() -> None:
    """Controller logout delegates session termination orchestration to backend."""
    transport = MagicMock()
    transport.read_token = AsyncMock(return_value="transport-token")
    strategy = _make_minimal_strategy()
    backend = AuthenticationBackend(name="test", transport=transport, strategy=cast("Any", strategy))
    backend_any = cast("Any", backend)
    backend_any.terminate_session = AsyncMock(return_value=Response(content=None))
    controller_class = create_auth_controller(
        backend=backend,
    )
    controller = cast("Any", controller_class(owner=MagicMock()))

    request = MagicMock()
    request.user = _MinimalUser()

    logout_handler = controller.logout.fn
    response = await logout_handler(controller, request)

    assert isinstance(response, Response)
    backend_any.terminate_session.assert_awaited_once_with(request, request.user)
    transport.read_token.assert_not_called()


class _MinimalUser:
    """Minimal user double for logout handler tests."""

    def __init__(self) -> None:
        self.id = uuid4()
        self.email = "u@example.com"
        self.is_active = True
        self.is_verified = True
        self.is_superuser = False


def _make_minimal_strategy() -> Strategy[_MinimalUser, UUID]:
    """Return a minimal strategy for controller construction."""

    class S(Strategy[_MinimalUser, UUID]):
        async def read_token(
            self,
            token: str | None,
            user_manager: UserManagerProtocol[_MinimalUser, UUID],
        ) -> _MinimalUser | None:
            return None

        async def write_token(self, user: _MinimalUser) -> str:
            return "t"

        async def destroy_token(self, token: str, user: _MinimalUser) -> None:
            pass

    return S()


class _TransportReturningNone(BearerTransport):
    """Transport whose read_token returns None to exercise logout credential check."""

    async def read_token(self, connection: object) -> None:
        """Always return None so logout handler raises NotAuthorizedException."""
        return


async def test_logout_clears_cookie_auth_and_refresh_cookies() -> None:
    """Logout expires auth and refresh cookies for cookie+refresh flows."""

    class _RefreshEnabledStrategy(Strategy[_MinimalUser, UUID]):
        async def read_token(
            self,
            token: str | None,
            user_manager: UserManagerProtocol[_MinimalUser, UUID],
        ) -> _MinimalUser | None:
            del token
            del user_manager
            return None

        async def write_token(self, user: _MinimalUser) -> str:
            del user
            return "access-token"

        async def destroy_token(self, token: str, user: _MinimalUser) -> None:
            del token
            del user

        async def write_refresh_token(self, user: _MinimalUser) -> str:
            del user
            return "refresh-token"

        async def rotate_refresh_token(
            self,
            refresh_token: str,
            user_manager: UserManagerProtocol[_MinimalUser, UUID],
        ) -> tuple[_MinimalUser, str] | None:
            del refresh_token
            del user_manager
            return None

    transport = CookieTransport(cookie_name="litestar_auth")
    strategy = _RefreshEnabledStrategy()
    backend = AuthenticationBackend(name="test", transport=transport, strategy=cast("Any", strategy))

    controller_class = create_auth_controller(
        backend=backend,
        enable_refresh=True,
    )
    controller = cast("Any", controller_class(owner=MagicMock()))

    request = MagicMock()
    request.user = _MinimalUser()
    request.cookies = {"litestar_auth": "access-cookie-value"}

    logout_handler = controller.logout.fn
    logout_response = await logout_handler(controller, request)

    refresh_cookie = next(cookie for cookie in logout_response.cookies if cookie.key == "litestar_auth_refresh")
    assert refresh_cookie.max_age == 0
    assert not refresh_cookie.value

    auth_cookie = next(cookie for cookie in logout_response.cookies if cookie.key == "litestar_auth")
    assert auth_cookie.max_age == 0
    assert not auth_cookie.value


def _make_closure_cell(value: object) -> CellType:
    """Return a closure cell containing ``value`` for function reconstruction."""

    def _cell_factory() -> object:
        return value

    closure = _cell_factory.__closure__
    assert closure is not None
    return closure[0]


async def test_login_rate_limit_before_request_is_a_noop_when_rate_limit_cell_is_none() -> None:
    """The login before_request hook exits cleanly when no limiter is configured."""

    class _RateLimitedStrategy(Strategy[_MinimalUser, UUID]):
        async def read_token(
            self,
            token: str | None,
            user_manager: UserManagerProtocol[_MinimalUser, UUID],
        ) -> _MinimalUser | None:
            del token
            del user_manager
            return None

        async def write_token(self, user: _MinimalUser) -> str:
            del user
            return "access-token"

        async def destroy_token(self, token: str, user: _MinimalUser) -> None:
            del token
            del user

    rate_limit = MagicMock()
    rate_limit.before_request = AsyncMock()
    backend = AuthenticationBackend(
        name="test",
        transport=BearerTransport(),
        strategy=cast("Any", _RateLimitedStrategy()),
    )
    controller_class = create_auth_controller(
        backend=backend,
        rate_limit_config=cast("Any", MagicMock(login=rate_limit)),
    )
    before_request = cast("Any", controller_class).login.before_request
    no_limit_before_request = FunctionType(
        before_request.__code__,
        before_request.__globals__,
        name=before_request.__name__,
        closure=(_make_closure_cell(None),),
    )

    await no_limit_before_request(MagicMock())

    rate_limit.before_request.assert_not_awaited()


async def test_refresh_rate_limit_before_request_is_a_noop_when_rate_limit_cell_is_none() -> None:
    """The refresh before_request hook exits cleanly when no limiter is configured."""

    class _RefreshEnabledStrategy(Strategy[_MinimalUser, UUID]):
        async def read_token(
            self,
            token: str | None,
            user_manager: UserManagerProtocol[_MinimalUser, UUID],
        ) -> _MinimalUser | None:
            del token
            del user_manager
            return None

        async def write_token(self, user: _MinimalUser) -> str:
            del user
            return "access-token"

        async def destroy_token(self, token: str, user: _MinimalUser) -> None:
            del token
            del user

        async def write_refresh_token(self, user: _MinimalUser) -> str:
            del user
            return "refresh-token"

        async def rotate_refresh_token(
            self,
            refresh_token: str,
            user_manager: UserManagerProtocol[_MinimalUser, UUID],
        ) -> tuple[_MinimalUser, str] | None:
            del refresh_token
            del user_manager
            return _MinimalUser(), "rotated-refresh-token"

    rate_limit = MagicMock()
    rate_limit.before_request = AsyncMock()
    backend = AuthenticationBackend(
        name="test",
        transport=BearerTransport(),
        strategy=cast("Any", _RefreshEnabledStrategy()),
    )
    controller_class = create_auth_controller(
        backend=backend,
        rate_limit_config=cast("Any", MagicMock(refresh=rate_limit)),
        enable_refresh=True,
    )
    before_request = cast("Any", controller_class).refresh.before_request
    no_limit_before_request = FunctionType(
        before_request.__code__,
        before_request.__globals__,
        name=before_request.__name__,
        closure=(_make_closure_cell(None),),
    )

    await no_limit_before_request(MagicMock())

    rate_limit.before_request.assert_not_awaited()


async def test_refresh_rejects_inactive_user_without_global_invalidation_hook() -> None:
    """Refresh still raises the user-state error when invalidate_all_tokens is unavailable."""

    class _RefreshEnabledStrategy(Strategy[_MinimalUser, UUID]):
        async def read_token(
            self,
            token: str | None,
            user_manager: UserManagerProtocol[_MinimalUser, UUID],
        ) -> _MinimalUser | None:
            del token
            del user_manager
            return None

        async def write_token(self, user: _MinimalUser) -> str:
            del user
            return "access-token"

        async def destroy_token(self, token: str, user: _MinimalUser) -> None:
            del token
            del user

        async def write_refresh_token(self, user: _MinimalUser) -> str:
            del user
            return "refresh-token"

        async def rotate_refresh_token(
            self,
            refresh_token: str,
            user_manager: UserManagerProtocol[_MinimalUser, UUID],
        ) -> tuple[_MinimalUser, str] | None:
            del refresh_token
            del user_manager
            user = _MinimalUser()
            user.is_active = False
            return user, "rotated-refresh-token"

    backend = AuthenticationBackend(
        name="test",
        transport=BearerTransport(),
        strategy=cast("Any", _RefreshEnabledStrategy()),
    )
    um = MagicMock()
    um.require_account_state.side_effect = InactiveUserError()
    controller_class = create_auth_controller(
        backend=backend,
        enable_refresh=True,
    )
    controller = cast("Any", controller_class(owner=MagicMock()))
    request = MagicMock()

    with pytest.raises(ClientException) as exc_info:
        await controller.refresh.fn(
            controller,
            request,
            data=cast("Any", MagicMock(refresh_token="refresh-token")),
            **{DEFAULT_USER_MANAGER_DEPENDENCY_KEY: um},
        )

    assert exc_info.value.extra == {"code": ErrorCode.LOGIN_USER_INACTIVE}


async def test_refresh_invalidates_all_tokens_for_protocol_matching_strategy() -> None:
    """Refresh revokes all artifacts when account-state validation fails after rotation."""

    class _RefreshEnabledStrategy(Strategy[_MinimalUser, UUID]):
        def __init__(self) -> None:
            self.invalidate_all_tokens = AsyncMock()

        async def read_token(
            self,
            token: str | None,
            user_manager: UserManagerProtocol[_MinimalUser, UUID],
        ) -> _MinimalUser | None:
            del token
            del user_manager
            return None

        async def write_token(self, user: _MinimalUser) -> str:
            del user
            return "access-token"

        async def destroy_token(self, token: str, user: _MinimalUser) -> None:
            del token
            del user

        async def write_refresh_token(self, user: _MinimalUser) -> str:
            del user
            return "refresh-token"

        async def rotate_refresh_token(
            self,
            refresh_token: str,
            user_manager: UserManagerProtocol[_MinimalUser, UUID],
        ) -> tuple[_MinimalUser, str] | None:
            del refresh_token
            del user_manager
            user = _MinimalUser()
            user.is_active = False
            return user, "rotated-refresh-token"

    strategy = _RefreshEnabledStrategy()
    backend = AuthenticationBackend(
        name="test",
        transport=BearerTransport(),
        strategy=cast("Any", strategy),
    )
    um = MagicMock()
    um.require_account_state.side_effect = InactiveUserError()
    controller_class = create_auth_controller(
        backend=backend,
        enable_refresh=True,
    )
    controller = cast("Any", controller_class(owner=MagicMock()))
    request = MagicMock()

    with pytest.raises(ClientException) as exc_info:
        await controller.refresh.fn(
            controller,
            request,
            data=cast("Any", MagicMock(refresh_token="refresh-token")),
            **{DEFAULT_USER_MANAGER_DEPENDENCY_KEY: um},
        )

    assert exc_info.value.extra == {"code": ErrorCode.LOGIN_USER_INACTIVE}
    strategy.invalidate_all_tokens.assert_awaited_once()


async def test_login_uses_manager_account_state_validator_when_available() -> None:
    """Login delegates account-state validation to the injected user manager when provided."""

    class _LoginStrategy(Strategy[_MinimalUser, UUID]):
        async def read_token(
            self,
            token: str | None,
            user_manager: UserManagerProtocol[_MinimalUser, UUID],
        ) -> _MinimalUser | None:
            del token
            del user_manager
            return None

        async def write_token(self, user: _MinimalUser) -> str:
            del user
            return "access-token"

        async def destroy_token(self, token: str, user: _MinimalUser) -> None:
            del token
            del user

    backend = AuthenticationBackend(
        name="test",
        transport=BearerTransport(),
        strategy=cast("Any", _LoginStrategy()),
    )
    controller_class = create_auth_controller(backend=backend)
    controller = cast("Any", controller_class(owner=MagicMock()))
    request = MagicMock()
    data = LoginCredentials(identifier="user@example.com", password="correct-password")
    user = _MinimalUser()
    user.is_active = False
    user_manager = MagicMock()
    user_manager.authenticate = AsyncMock(return_value=user)
    user_manager.on_after_login = AsyncMock()
    user_manager.require_account_state = MagicMock()

    response = await controller.login.fn(
        controller,
        request,
        data,
        **{DEFAULT_USER_MANAGER_DEPENDENCY_KEY: user_manager},
    )

    assert isinstance(response, Response)
    user_manager.require_account_state.assert_called_once_with(user, require_verified=False)


async def test_login_rejects_invalid_identifier_before_authentication() -> None:
    """Login raises a 422 when the identifier does not match the configured login mode."""
    backend = AuthenticationBackend(
        name="test",
        transport=BearerTransport(),
        strategy=cast("Any", _make_minimal_strategy()),
    )
    ctx = _make_auth_controller_context(
        backend=backend,
        rate_limit_config=None,
        enable_refresh=False,
        requires_verification=False,
        login_identifier="email",
        totp_pending_secret=None,
        totp_pending_lifetime=timedelta(minutes=5),
    )
    request = MagicMock()
    user_manager = MagicMock()
    user_manager.authenticate = AsyncMock()
    data = LoginCredentials(identifier="not-an-email", password="correct-password")

    with pytest.raises(ClientException) as exc_info:
        await auth_controller_module._handle_auth_login(
            request,
            data,
            ctx=ctx,
            user_manager=user_manager,
        )

    assert exc_info.value.status_code == STATUS_UNPROCESSABLE_ENTITY
    assert exc_info.value.extra == {"code": ErrorCode.LOGIN_PAYLOAD_INVALID}
    user_manager.authenticate.assert_not_awaited()


async def test_login_returns_pending_token_when_totp_enabled() -> None:
    """Login returns the pending 2FA payload instead of a full session when TOTP is enabled."""

    class _TotpUser(_MinimalUser):
        def __init__(self) -> None:
            super().__init__()
            self.totp_secret = "stored-secret"

    backend = AuthenticationBackend(
        name="test",
        transport=BearerTransport(),
        strategy=cast("Any", _make_minimal_strategy()),
    )
    ctx = _make_auth_controller_context(
        backend=backend,
        rate_limit_config=None,
        enable_refresh=False,
        requires_verification=False,
        login_identifier="email",
        totp_pending_secret="pending-secret-for-unit-tests-1234",
        totp_pending_lifetime=timedelta(minutes=5),
    )
    request = MagicMock()
    data = LoginCredentials(identifier="user@example.com", password="correct-password")
    user = _TotpUser()
    user_manager = MagicMock()
    user_manager.authenticate = AsyncMock(return_value=user)
    user_manager.on_after_login = AsyncMock()
    user_manager.read_totp_secret = AsyncMock(return_value="JBSWY3DPEHPK3PXP")
    user_manager.require_account_state = MagicMock()

    response = await auth_controller_module._handle_auth_login(
        request,
        data,
        ctx=ctx,
        user_manager=user_manager,
    )

    assert isinstance(response, Response)
    payload = cast("dict[str, object]", response.content)
    assert response.status_code == HTTP_ACCEPTED
    assert payload["totp_required"] is True
    assert isinstance(payload["pending_token"], str)
    user_manager.require_account_state.assert_called_once_with(user, require_verified=False)
    user_manager.on_after_login.assert_not_awaited()


async def test_login_falls_back_to_full_login_when_totp_pending_token_is_not_issued() -> None:
    """TOTP-enabled login still completes when the user has no configured TOTP secret."""

    class _TotpUser(_MinimalUser):
        def __init__(self) -> None:
            super().__init__()
            self.totp_secret: str | None = None

    backend = AuthenticationBackend(
        name="test",
        transport=BearerTransport(),
        strategy=cast("Any", _make_minimal_strategy()),
    )
    ctx = _make_auth_controller_context(
        backend=backend,
        rate_limit_config=None,
        enable_refresh=False,
        requires_verification=False,
        login_identifier="email",
        totp_pending_secret="pending-secret-for-unit-tests-1234",
        totp_pending_lifetime=timedelta(minutes=5),
    )
    request = MagicMock()
    data = LoginCredentials(identifier="user@example.com", password="correct-password")
    user = _TotpUser()
    user_manager = MagicMock()
    user_manager.authenticate = AsyncMock(return_value=user)
    user_manager.on_after_login = AsyncMock()
    user_manager.read_totp_secret = AsyncMock(return_value=None)
    user_manager.require_account_state = MagicMock()

    response = await auth_controller_module._handle_auth_login(
        request,
        data,
        ctx=ctx,
        user_manager=user_manager,
    )

    assert isinstance(response, Response)
    assert response.content == {"access_token": "t", "token_type": "bearer"}
    user_manager.on_after_login.assert_awaited_once_with(user)


async def test_login_raises_configuration_error_when_totp_user_protocol_is_missing() -> None:
    """A configured TOTP pending flow requires the authenticated user to expose TOTP fields."""
    backend = AuthenticationBackend(
        name="test",
        transport=BearerTransport(),
        strategy=cast("Any", _make_minimal_strategy()),
    )
    ctx = _make_auth_controller_context(
        backend=backend,
        rate_limit_config=None,
        enable_refresh=False,
        requires_verification=False,
        login_identifier="email",
        totp_pending_secret="pending-secret-for-unit-tests-1234",
        totp_pending_lifetime=timedelta(minutes=5),
    )
    request = MagicMock()
    data = LoginCredentials(identifier="user@example.com", password="correct-password")
    user_manager = MagicMock()
    user_manager.authenticate = AsyncMock(return_value=_MinimalUser())
    user_manager.on_after_login = AsyncMock()
    user_manager.require_account_state = MagicMock()

    with pytest.raises(ConfigurationError, match="does not implement TOTP fields"):
        await auth_controller_module._handle_auth_login(
            request,
            data,
            ctx=ctx,
            user_manager=user_manager,
        )

    user_manager.on_after_login.assert_not_awaited()


async def test_refresh_rejects_invalid_token_and_increments_rate_limit() -> None:
    """Refresh increments the throttle and returns the stable invalid-token error."""

    class _RefreshEnabledStrategy(Strategy[_MinimalUser, UUID]):
        async def read_token(
            self,
            token: str | None,
            user_manager: UserManagerProtocol[_MinimalUser, UUID],
        ) -> _MinimalUser | None:
            del token
            del user_manager
            return None

        async def write_token(self, user: _MinimalUser) -> str:
            del user
            return "access-token"

        async def destroy_token(self, token: str, user: _MinimalUser) -> None:
            del token
            del user

        async def write_refresh_token(self, user: _MinimalUser) -> str:
            del user
            return "refresh-token"

        async def rotate_refresh_token(
            self,
            refresh_token: str,
            user_manager: UserManagerProtocol[_MinimalUser, UUID],
        ) -> tuple[_MinimalUser, str] | None:
            del refresh_token
            del user_manager
            return None

    refresh_rate_limit = MagicMock()
    refresh_rate_limit.increment = AsyncMock()
    refresh_rate_limit.reset = AsyncMock()
    backend = AuthenticationBackend(
        name="test",
        transport=BearerTransport(),
        strategy=cast("Any", _RefreshEnabledStrategy()),
    )
    ctx = _make_auth_controller_context(
        backend=backend,
        rate_limit_config=cast("Any", MagicMock(refresh=refresh_rate_limit)),
        enable_refresh=True,
        requires_verification=False,
        login_identifier="email",
        totp_pending_secret=None,
        totp_pending_lifetime=timedelta(minutes=5),
    )
    request = MagicMock()

    with pytest.raises(ClientException) as exc_info:
        await auth_controller_module._handle_auth_refresh(
            request,
            ctx=ctx,
            data=auth_controller_module.RefreshTokenRequest(refresh_token="invalid-refresh-token"),
            user_manager=cast("Any", MagicMock()),
        )

    assert exc_info.value.status_code == HTTP_BAD_REQUEST
    assert exc_info.value.extra == {"code": ErrorCode.REFRESH_TOKEN_INVALID}
    refresh_rate_limit.increment.assert_awaited_once_with(request)
    refresh_rate_limit.reset.assert_not_awaited()


async def test_refresh_success_returns_rotated_tokens_and_resets_rate_limit() -> None:
    """Successful refresh returns a new access token plus the rotated refresh token."""

    class _RefreshEnabledStrategy(Strategy[_MinimalUser, UUID]):
        async def read_token(
            self,
            token: str | None,
            user_manager: UserManagerProtocol[_MinimalUser, UUID],
        ) -> _MinimalUser | None:
            del token
            del user_manager
            return None

        async def write_token(self, user: _MinimalUser) -> str:
            del user
            return "new-access-token"

        async def destroy_token(self, token: str, user: _MinimalUser) -> None:
            del token
            del user

        async def write_refresh_token(self, user: _MinimalUser) -> str:
            del user
            return "refresh-token"

        async def rotate_refresh_token(
            self,
            refresh_token: str,
            user_manager: UserManagerProtocol[_MinimalUser, UUID],
        ) -> tuple[_MinimalUser, str] | None:
            del refresh_token
            del user_manager
            return _MinimalUser(), "rotated-refresh-token"

    refresh_rate_limit = MagicMock()
    refresh_rate_limit.increment = AsyncMock()
    refresh_rate_limit.reset = AsyncMock()
    backend = AuthenticationBackend(
        name="test",
        transport=BearerTransport(),
        strategy=cast("Any", _RefreshEnabledStrategy()),
    )
    ctx = _make_auth_controller_context(
        backend=backend,
        rate_limit_config=cast("Any", MagicMock(refresh=refresh_rate_limit)),
        enable_refresh=True,
        requires_verification=False,
        login_identifier="email",
        totp_pending_secret=None,
        totp_pending_lifetime=timedelta(minutes=5),
    )
    request = MagicMock()
    user_manager = MagicMock()
    user_manager.require_account_state = MagicMock()

    response = await auth_controller_module._handle_auth_refresh(
        request,
        ctx=ctx,
        data=auth_controller_module.RefreshTokenRequest(refresh_token="refresh-token"),
        user_manager=cast("Any", user_manager),
    )

    assert response.content == {
        "access_token": "new-access-token",
        "token_type": "bearer",
        "refresh_token": "rotated-refresh-token",
    }
    refresh_rate_limit.increment.assert_not_awaited()
    refresh_rate_limit.reset.assert_awaited_once_with(request)
    user_manager.require_account_state.assert_called_once()


def test_create_auth_controller_validates_totp_pending_secret_outside_testing(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The factory validates the TOTP pending secret length unless unsafe testing is enabled."""
    backend = AuthenticationBackend(
        name="test",
        transport=BearerTransport(),
        strategy=cast("Any", _make_minimal_strategy()),
    )
    validate_secret_length = MagicMock()
    monkeypatch.setattr(auth_controller_module, "validate_secret_length", validate_secret_length)

    create_auth_controller(
        backend=backend,
        totp_pending_secret="pending-secret-for-unit-tests-1234",
    )

    validate_secret_length.assert_called_once_with(
        "pending-secret-for-unit-tests-1234",
        label="totp_pending_secret",
    )


def _email_with_local_len(local_len: int) -> str:
    """Build ``local@b.co`` where the total length is ``local_len + len('@b.co')``.

    Returns:
        Email-shaped string with the given local-part length.
    """
    return f"{'a' * local_len}@b.co"


def test_resolve_login_identifier_email_mode_ok() -> None:
    """Email mode accepts a value matching the login email regex."""
    assert _resolve_login_identifier("user@example.com", "email") == "user@example.com"


def test_resolve_login_identifier_email_mode_invalid_format_raises() -> None:
    """Email mode rejects values that do not match the login email regex."""
    with pytest.raises(ClientException) as exc_info:
        _resolve_login_identifier("not-an-email", "email")

    assert exc_info.value.status_code == STATUS_UNPROCESSABLE_ENTITY
    assert exc_info.value.extra == {"code": ErrorCode.LOGIN_PAYLOAD_INVALID}


def test_resolve_login_identifier_email_mode_exceeds_max_length_raises() -> None:
    """Email mode rejects identifiers longer than 320 characters."""
    domain_suffix_len = len("@b.co")
    too_long = _email_with_local_len(_LOGIN_EMAIL_MAX_LENGTH + 1 - domain_suffix_len)
    assert len(too_long) == _LOGIN_EMAIL_MAX_LENGTH + 1

    with pytest.raises(ClientException) as exc_info:
        _resolve_login_identifier(too_long, "email")

    assert exc_info.value.status_code == STATUS_UNPROCESSABLE_ENTITY
    assert exc_info.value.extra == {"code": ErrorCode.LOGIN_PAYLOAD_INVALID}


def test_resolve_login_identifier_email_mode_at_max_length_ok() -> None:
    """Exactly 320 characters is accepted when the value matches the email pattern."""
    domain_suffix_len = len("@b.co")
    at_limit = _email_with_local_len(_LOGIN_EMAIL_MAX_LENGTH - domain_suffix_len)
    assert len(at_limit) == _LOGIN_EMAIL_MAX_LENGTH

    assert _resolve_login_identifier(at_limit, "email") == at_limit


def test_resolve_login_identifier_username_mode_basic() -> None:
    """Username mode accepts a non-email-shaped identifier."""
    assert _resolve_login_identifier("alice", "username") == "alice"


def test_resolve_login_identifier_username_mode_strips_whitespace() -> None:
    """Username mode strips leading and trailing whitespace."""
    assert _resolve_login_identifier("  alice  ", "username") == "alice"


def test_resolve_login_identifier_username_mode_empty_after_strip_raises() -> None:
    """Whitespace-only payload is rejected after strip."""
    with pytest.raises(ClientException) as exc_info:
        _resolve_login_identifier("   \t  ", "username")

    assert exc_info.value.status_code == STATUS_UNPROCESSABLE_ENTITY
    assert exc_info.value.extra == {"code": ErrorCode.LOGIN_PAYLOAD_INVALID}


def test_resolve_login_identifier_username_mode_too_long_raises() -> None:
    """Stripped length above 150 is rejected."""
    too_long = "a" * (_LOGIN_USERNAME_MAX_LENGTH + 1)
    with pytest.raises(ClientException) as exc_info:
        _resolve_login_identifier(too_long, "username")

    assert exc_info.value.status_code == STATUS_UNPROCESSABLE_ENTITY
    assert exc_info.value.extra == {"code": ErrorCode.LOGIN_PAYLOAD_INVALID}


def test_resolve_login_identifier_username_mode_at_max_length_ok() -> None:
    """Exactly 150 characters after strip is accepted."""
    at_limit = "a" * _LOGIN_USERNAME_MAX_LENGTH
    assert _resolve_login_identifier(at_limit, "username") == at_limit


def test_make_auth_controller_context_stores_login_identifier() -> None:
    """Context records email and username login_identifier modes."""
    transport = BearerTransport()
    strategy = _make_minimal_strategy()
    backend = AuthenticationBackend(name="test", transport=transport, strategy=cast("Any", strategy))

    ctx_email = _make_auth_controller_context(
        backend=backend,
        rate_limit_config=None,
        enable_refresh=False,
        requires_verification=False,
        login_identifier="email",
        totp_pending_secret=None,
        totp_pending_lifetime=timedelta(minutes=5),
    )
    assert ctx_email.login_identifier == "email"

    ctx_username = _make_auth_controller_context(
        backend=backend,
        rate_limit_config=None,
        enable_refresh=False,
        requires_verification=False,
        login_identifier="username",
        totp_pending_secret=None,
        totp_pending_lifetime=timedelta(minutes=5),
    )
    assert ctx_username.login_identifier == "username"


def test_create_auth_controller_accepts_username_login_identifier() -> None:
    """Factory accepts login_identifier=username and returns a controller class."""
    transport = BearerTransport()
    strategy = _make_minimal_strategy()
    backend = AuthenticationBackend(name="test", transport=transport, strategy=cast("Any", strategy))

    controller_class = create_auth_controller(backend=backend, login_identifier="username")
    assert controller_class.__name__.endswith("AuthController")
