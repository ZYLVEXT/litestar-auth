"""Integration tests for AsyncSession usage per HTTP request (plugin wiring)."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Self, cast
from uuid import UUID, uuid4

import pytest
from litestar import Litestar, Request, get
from litestar.testing import AsyncTestClient

import litestar_auth._plugin.database_token as database_token_module
from litestar_auth._plugin.config import DatabaseTokenAuthConfig
from litestar_auth.authentication.backend import AuthenticationBackend
from litestar_auth.authentication.transport.bearer import BearerTransport
from litestar_auth.manager import UserManagerSecurity
from litestar_auth.password import PasswordHelper
from litestar_auth.plugin import LitestarAuth, LitestarAuthConfig
from tests.integration.conftest import CountingSessionMaker, ExampleUser, InMemoryUserDatabase
from tests.integration.test_orchestrator import (
    InMemoryRefreshTokenStrategy,
    InMemoryTokenStrategy,
    PluginUserManager,
    auth_state,
    dependency_probe,
)

pytestmark = [pytest.mark.integration]

HTTP_CREATED = 201
HTTP_OK = 200


@get("/testing-session-contract", sync_to_thread=False)
def session_contract_route(
    request: Request[Any, Any, Any],
    db_session: object,
    litestar_auth_backends: object,
    litestar_auth_user_manager: object,
) -> dict[str, int | str | None]:
    """Expose same-request session bindings across middleware and handler DI.

    Returns:
        Authenticated user email plus the session identifiers seen by handler dependencies.
    """
    user = cast("ExampleUser | None", request.user)
    backends = cast("list[Any]", litestar_auth_backends)
    user_manager = cast("Any", litestar_auth_user_manager)
    backend_strategy = backends[0].strategy
    manager_backend_strategy = user_manager.backends[0].strategy
    session = cast("Any", db_session)
    session_id = cast("int", session.session_id)
    return {
        "email": user.email if user is not None else None,
        "db_session_id": session_id,
        "backend_session_id": cast("int", backend_strategy._session.session_id),
        "manager_session_id": cast("int", manager_backend_strategy._session.session_id),
    }


@dataclass(slots=True)
class _PresetStrategyState:
    """Shared token storage and session observations for the fake DB preset backend."""

    access_tokens: dict[str, UUID] = field(default_factory=dict)
    refresh_tokens: dict[str, UUID] = field(default_factory=dict)
    write_session_ids: list[int] = field(default_factory=list)
    read_session_ids: list[int] = field(default_factory=list)
    destroy_session_ids: list[int] = field(default_factory=list)
    refresh_write_session_ids: list[int] = field(default_factory=list)
    rotate_session_ids: list[int] = field(default_factory=list)
    invalidate_session_ids: list[int] = field(default_factory=list)
    access_counter: int = 0
    refresh_counter: int = 0


@dataclass(slots=True)
class _PresetSession:
    """Request-local session stub carrying a stable identifier for assertions."""

    session_id: int

    async def __aenter__(self) -> Self:
        """Enter async context for middleware/session lifecycle parity.

        Returns:
            This session instance.
        """
        return self

    async def __aexit__(
        self,
        exc_type: type[BaseException] | None,
        exc: BaseException | None,
        traceback: object,
    ) -> None:
        """Exit async context (no-op)."""
        del exc_type, exc, traceback

    async def close(self) -> None:
        """Match ``AsyncSession.close()`` for before-send hooks."""

    async def commit(self) -> None:
        """Match ``AsyncSession.commit()`` for before-send hooks."""

    async def rollback(self) -> None:
        """Match ``AsyncSession.rollback()`` for before-send hooks."""


class _PresetSessionMaker:
    """Counting session factory for DB-preset lifecycle tests."""

    def __init__(self) -> None:
        """Initialize the call counter."""
        self.call_count = 0

    def __call__(self) -> _PresetSession:
        """Return a request-local session tagged with a stable counter.

        Returns:
            Session stub representing the current request-local session.
        """
        self.call_count += 1
        return _PresetSession(session_id=self.call_count)


class _PresetSessionStrategy:
    """Refresh-capable in-memory strategy that records the request session used."""

    def __init__(
        self,
        *,
        state: _PresetStrategyState,
        session: object,
        token_prefix: str,
    ) -> None:
        """Store shared token state and the current session binding."""
        self._state = state
        self._session = session
        self._token_prefix = token_prefix

    def _session_id(self) -> int:
        """Return the current request-session identifier.

        Returns:
            Integer identifier for the current request-local session.
        """
        return cast("int", cast("Any", self._session).session_id)

    def with_session(self, session: object) -> _PresetSessionStrategy:
        """Clone the strategy while keeping shared token state.

        Returns:
            Strategy instance bound to the provided request session.
        """
        return type(self)(state=self._state, session=session, token_prefix=self._token_prefix)

    async def read_token(self, token: str | None, user_manager: object) -> ExampleUser | None:
        """Resolve a stored token and record which request session performed the read.

        Returns:
            The matching user, or ``None`` when the token is absent or unknown.
        """
        if token is None:
            return None
        self._state.read_session_ids.append(self._session_id())
        user_id = self._state.access_tokens.get(token)
        if user_id is None:
            return None
        return await cast("Any", user_manager).get(user_id)

    async def write_token(self, user: ExampleUser) -> str:
        """Issue an access token and record the request session used.

        Returns:
            Newly issued access token value.
        """
        self._state.write_session_ids.append(self._session_id())
        self._state.access_counter += 1
        token = f"{self._token_prefix}-access-{self._state.access_counter}"
        self._state.access_tokens[token] = user.id
        return token

    async def destroy_token(self, token: str, user: ExampleUser) -> None:
        """Delete an access token and record the request session used."""
        del user
        self._state.destroy_session_ids.append(self._session_id())
        self._state.access_tokens.pop(token, None)

    async def write_refresh_token(self, user: ExampleUser) -> str:
        """Issue a refresh token and record the request session used.

        Returns:
            Newly issued refresh token value.
        """
        self._state.refresh_write_session_ids.append(self._session_id())
        self._state.refresh_counter += 1
        token = f"{self._token_prefix}-refresh-{self._state.refresh_counter}"
        self._state.refresh_tokens[token] = user.id
        return token

    async def rotate_refresh_token(self, refresh_token: str, user_manager: object) -> tuple[ExampleUser, str] | None:
        """Rotate a refresh token and record the request session used.

        Returns:
            The resolved user plus the rotated refresh token, or ``None``.
        """
        self._state.rotate_session_ids.append(self._session_id())
        user_id = self._state.refresh_tokens.pop(refresh_token, None)
        if user_id is None:
            return None
        user = await cast("Any", user_manager).get(user_id)
        if user is None:
            return None
        return user, await self.write_refresh_token(user)

    async def invalidate_all_tokens(self, user: ExampleUser) -> None:
        """Invalidate all tokens for the provided user within the current request session."""
        self._state.invalidate_session_ids.append(self._session_id())
        self._state.access_tokens = {
            token: user_id for token, user_id in self._state.access_tokens.items() if user_id != user.id
        }
        self._state.refresh_tokens = {
            token: user_id for token, user_id in self._state.refresh_tokens.items() if user_id != user.id
        }


def _build_app_with_counting_session_maker() -> tuple[Litestar, CountingSessionMaker]:
    """LitestarAuth app with :class:`CountingSessionMaker` (same shape as orchestrator tests).

    Returns:
        Application instance and the counting session factory for assertions.
    """
    password_helper = PasswordHelper()
    regular_user = ExampleUser(
        id=uuid4(),
        email="user@example.com",
        hashed_password=password_helper.hash("user-password"),
        is_verified=True,
    )
    user_db = InMemoryUserDatabase([regular_user])
    primary_strategy = InMemoryTokenStrategy(token_prefix="primary")
    secondary_strategy = InMemoryTokenStrategy(token_prefix="secondary")
    backends = [
        AuthenticationBackend[ExampleUser, UUID](
            name="primary",
            transport=BearerTransport(),
            strategy=cast("Any", primary_strategy),
        ),
        AuthenticationBackend[ExampleUser, UUID](
            name="secondary",
            transport=BearerTransport(),
            strategy=cast("Any", secondary_strategy),
        ),
    ]
    counting = CountingSessionMaker()
    config = LitestarAuthConfig[ExampleUser, UUID](
        backends=backends,
        session_maker=cast("Any", counting),
        user_model=ExampleUser,
        user_manager_class=PluginUserManager,
        user_db_factory=lambda _session: user_db,
        user_manager_security=UserManagerSecurity[UUID](
            verification_token_secret="verify-secret-12345678901234567890",
            reset_password_token_secret="reset-secret-123456789012345678901",
            id_parser=UUID,
            password_helper=password_helper,
        ),
        include_users=True,
    )
    plugin = LitestarAuth(config)
    app = Litestar(route_handlers=[dependency_probe, auth_state], plugins=[plugin])
    return app, counting


def _build_refresh_app_with_counting_session_maker() -> tuple[Litestar, CountingSessionMaker]:
    """LitestarAuth app with refresh enabled for per-request session assertions.

    Returns:
        Application instance and the counting session factory for assertions.
    """
    password_helper = PasswordHelper()
    regular_user = ExampleUser(
        id=uuid4(),
        email="user@example.com",
        hashed_password=password_helper.hash("user-password"),
        is_verified=True,
    )
    user_db = InMemoryUserDatabase([regular_user])
    counting = CountingSessionMaker()
    config = LitestarAuthConfig[ExampleUser, UUID](
        backends=[
            AuthenticationBackend[ExampleUser, UUID](
                name="primary",
                transport=BearerTransport(),
                strategy=cast("Any", InMemoryRefreshTokenStrategy(token_prefix="primary")),
            ),
        ],
        session_maker=cast("Any", counting),
        user_model=ExampleUser,
        user_manager_class=PluginUserManager,
        user_db_factory=lambda _session: user_db,
        user_manager_security=UserManagerSecurity[UUID](
            verification_token_secret="verify-secret-12345678901234567890",
            reset_password_token_secret="reset-secret-123456789012345678901",
            id_parser=UUID,
            password_helper=password_helper,
        ),
        enable_refresh=True,
        include_users=False,
    )
    plugin = LitestarAuth(config)
    return Litestar(plugins=[plugin]), counting


def _install_preset_backend_builder(
    monkeypatch: pytest.MonkeyPatch,
) -> dict[int, _PresetStrategyState]:
    """Replace the DB-token preset backend builder with a session-tracking in-memory fake.

    Returns:
        Mapping from preset-config identity to the shared fake backend state.
    """
    states: dict[int, _PresetStrategyState] = {}

    def _build_backend(
        database_token_auth: DatabaseTokenAuthConfig,
        *,
        session: object | None = None,
        unsafe_testing: bool = False,
    ) -> AuthenticationBackend[ExampleUser, UUID]:
        """Build a fake preset backend bound to the provided request session.

        Returns:
            Authentication backend that shares the preset's in-memory token state.
        """
        del unsafe_testing
        state = states.setdefault(id(database_token_auth), _PresetStrategyState())
        strategy = _PresetSessionStrategy(
            state=state,
            session=cast("Any", session),
            token_prefix=database_token_auth.backend_name,
        )
        return AuthenticationBackend[ExampleUser, UUID](
            name=database_token_auth.backend_name,
            transport=BearerTransport(),
            strategy=cast("Any", strategy),
        )

    monkeypatch.setattr(database_token_module, "_build_database_token_backend", _build_backend)
    return states


def _build_database_token_preset_app(
    monkeypatch: pytest.MonkeyPatch,
    *,
    enable_refresh: bool = False,
) -> tuple[Litestar, _PresetSessionMaker, _PresetStrategyState]:
    """Build an app that exercises the preset runtime path without a startup DB session.

    Returns:
        Application instance, counting session factory, and fake preset backend state.
    """
    states = _install_preset_backend_builder(monkeypatch)
    password_helper = PasswordHelper()
    regular_user = ExampleUser(
        id=uuid4(),
        email="user@example.com",
        hashed_password=password_helper.hash("user-password"),
        is_verified=True,
    )
    user_db = InMemoryUserDatabase([regular_user])
    counting = _PresetSessionMaker()
    database_token_auth = DatabaseTokenAuthConfig(
        token_hash_secret="database-token-secret-12345678901234567890",
    )
    config = LitestarAuthConfig[ExampleUser, UUID](
        database_token_auth=database_token_auth,
        session_maker=cast("Any", counting),
        user_model=ExampleUser,
        user_manager_class=PluginUserManager,
        user_db_factory=lambda _session: user_db,
        user_manager_security=UserManagerSecurity[UUID](
            verification_token_secret="verify-secret-12345678901234567890",
            reset_password_token_secret="reset-secret-123456789012345678901",
            id_parser=UUID,
            password_helper=password_helper,
        ),
        enable_refresh=enable_refresh,
        include_users=False,
    )
    plugin = LitestarAuth(config)
    app = Litestar(route_handlers=[auth_state, session_contract_route], plugins=[plugin])
    return app, counting, states[id(database_token_auth)]


@pytest.mark.asyncio
async def test_single_session_per_request() -> None:
    """Exactly one ``session_maker()`` call per request (login + users controller)."""
    app, counting = _build_app_with_counting_session_maker()
    async with AsyncTestClient(app=app) as client:
        before_login = counting.call_count
        login_response = await client.post(
            "/auth/login",
            json={"identifier": "user@example.com", "password": "user-password"},
        )
        login_sessions = counting.call_count - before_login

        assert login_response.status_code == HTTP_CREATED
        token = login_response.json()["access_token"]

        before_me = counting.call_count
        me_response = await client.get(
            "/users/me",
            headers={"Authorization": f"Bearer {token}"},
        )
        me_sessions = counting.call_count - before_me

    assert me_response.status_code == HTTP_OK
    assert login_sessions == 1
    assert me_sessions == 1


@pytest.mark.asyncio
async def test_refresh_enabled_requests_still_use_one_session_each() -> None:
    """Login and refresh on the canonical bearer flow each allocate one request-local session."""
    app, counting = _build_refresh_app_with_counting_session_maker()
    async with AsyncTestClient(app=app) as client:
        before_login = counting.call_count
        login_response = await client.post(
            "/auth/login",
            json={"identifier": "user@example.com", "password": "user-password"},
        )
        login_sessions = counting.call_count - before_login

        assert login_response.status_code == HTTP_CREATED
        refresh_token = login_response.json()["refresh_token"]

        before_refresh = counting.call_count
        refresh_response = await client.post(
            "/auth/refresh",
            json={"refresh_token": refresh_token},
        )
        refresh_sessions = counting.call_count - before_refresh

    assert refresh_response.status_code == HTTP_CREATED
    assert login_sessions == 1
    assert refresh_sessions == 1


@pytest.mark.asyncio
async def test_database_token_preset_login_authenticate_logout_use_one_session_each(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The DB preset reuses one request-local session per login, authenticate, and logout request."""
    app, counting, state = _build_database_token_preset_app(monkeypatch)

    assert counting.call_count == 0

    async with AsyncTestClient(app=app) as client:
        before_login = counting.call_count
        login_response = await client.post(
            "/auth/login",
            json={"identifier": "user@example.com", "password": "user-password"},
        )
        login_sessions = counting.call_count - before_login

        assert login_response.status_code == HTTP_CREATED
        token = login_response.json()["access_token"]

        before_authenticate = counting.call_count
        auth_response = await client.get(
            "/auth-state",
            headers={"Authorization": f"Bearer {token}"},
        )
        authenticate_sessions = counting.call_count - before_authenticate

        before_logout = counting.call_count
        logout_response = await client.post(
            "/auth/logout",
            headers={"Authorization": f"Bearer {token}"},
        )
        logout_sessions = counting.call_count - before_logout

    assert auth_response.status_code == HTTP_OK
    assert auth_response.json() == {"email": "user@example.com"}
    assert logout_response.status_code == HTTP_CREATED
    assert login_sessions == 1
    assert authenticate_sessions == 1
    assert logout_sessions == 1
    assert state.write_session_ids == [1]
    assert state.read_session_ids == [2, 3]
    assert state.invalidate_session_ids == [3]
    assert state.destroy_session_ids == [3]


@pytest.mark.asyncio
async def test_database_token_preset_shares_same_session_across_middleware_and_handler_di(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """One authenticated request reuses the same session across middleware and handler DI."""
    app, counting, state = _build_database_token_preset_app(monkeypatch)

    assert counting.call_count == 0

    async with AsyncTestClient(app=app) as client:
        login_response = await client.post(
            "/auth/login",
            json={"identifier": "user@example.com", "password": "user-password"},
        )

        assert login_response.status_code == HTTP_CREATED
        token = login_response.json()["access_token"]

        before_contract = counting.call_count
        contract_response = await client.get(
            "/testing-session-contract",
            headers={"Authorization": f"Bearer {token}"},
        )
        contract_sessions = counting.call_count - before_contract

    payload = contract_response.json()

    assert contract_response.status_code == HTTP_OK
    assert state.write_session_ids == [1]
    assert state.read_session_ids == [cast("int", payload["db_session_id"])]
    assert counting.call_count == len(state.write_session_ids) + len(state.read_session_ids)
    assert contract_sessions == 1
    assert payload["email"] == "user@example.com"
    assert payload["backend_session_id"] == payload["db_session_id"]
    assert payload["manager_session_id"] == payload["db_session_id"]


@pytest.mark.asyncio
async def test_database_token_preset_refresh_uses_one_session_per_request(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The DB preset login and refresh flows avoid any startup template-session leakage."""
    app, counting, state = _build_database_token_preset_app(monkeypatch, enable_refresh=True)

    assert counting.call_count == 0

    async with AsyncTestClient(app=app) as client:
        before_login = counting.call_count
        login_response = await client.post(
            "/auth/login",
            json={"identifier": "user@example.com", "password": "user-password"},
        )
        login_sessions = counting.call_count - before_login

        assert login_response.status_code == HTTP_CREATED
        refresh_token = login_response.json()["refresh_token"]

        before_refresh = counting.call_count
        refresh_response = await client.post(
            "/auth/refresh",
            json={"refresh_token": refresh_token},
        )
        refresh_sessions = counting.call_count - before_refresh

    assert refresh_response.status_code == HTTP_CREATED
    assert login_sessions == 1
    assert refresh_sessions == 1
    assert state.write_session_ids == [1, 2]
    assert state.refresh_write_session_ids == [1, 2]
    assert state.rotate_session_ids == [2]
