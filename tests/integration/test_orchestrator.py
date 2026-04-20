"""Integration tests for the Litestar auth plugin/orchestrator."""

from __future__ import annotations

from dataclasses import is_dataclass
from functools import partial
from typing import TYPE_CHECKING, Any, Self, cast
from uuid import UUID, uuid4

import msgspec
import pytest
from cryptography.fernet import Fernet
from litestar import Litestar, Request, get
from litestar.exceptions import ClientException
from litestar.plugins import InitPlugin
from litestar.testing import AsyncTestClient

import litestar_auth.totp as _totp_mod
from litestar_auth._plugin.config import TotpConfig
from litestar_auth.authentication.backend import AuthenticationBackend
from litestar_auth.authentication.strategy.base import Strategy, UserManagerProtocol
from litestar_auth.authentication.strategy.jwt import InMemoryJWTDenylistStore
from litestar_auth.authentication.transport.bearer import BearerTransport
from litestar_auth.config import require_password_length
from litestar_auth.controllers.totp import INVALID_TOTP_TOKEN_DETAIL
from litestar_auth.exceptions import ErrorCode
from litestar_auth.manager import BaseUserManager, UserManagerSecurity
from litestar_auth.password import PasswordHelper
from litestar_auth.plugin import LitestarAuth, LitestarAuthConfig
from litestar_auth.totp import InMemoryUsedTotpCodeStore, _current_counter, _generate_totp_code
from tests.integration.conftest import ExampleUser, InMemoryUserDatabase

if TYPE_CHECKING:
    from types import TracebackType

    from litestar_auth.db.base import BaseUserStore

pytestmark = [pytest.mark.integration]

HTTP_ACCEPTED = 202
HTTP_BAD_REQUEST = 400
HTTP_UNPROCESSABLE_ENTITY = 422
HTTP_CREATED = 201
HTTP_OK = 200
TOTAL_USERS = 3


class PluginUserManager(BaseUserManager[ExampleUser, UUID]):
    """Concrete manager exposing paginated listings for plugin tests."""

    async def list_users(self, *, offset: int, limit: int) -> tuple[list[ExampleUser], int]:
        """Return users ordered by insertion with total count metadata."""
        return await self.user_db.list_users(offset=offset, limit=limit)


class TokenCaptureUserManager(PluginUserManager):
    """Plugin test manager that records generated out-of-band tokens."""

    def __init__(  # noqa: PLR0913
        self,
        user_db: BaseUserStore[ExampleUser, UUID],
        *,
        password_helper: PasswordHelper | None = None,
        verification_token_secret: str,
        reset_password_token_secret: str,
        id_parser: type[UUID],
        backends: tuple[object, ...] = (),
    ) -> None:
        """Initialize token capture storage alongside the base manager."""
        super().__init__(
            user_db,
            password_helper=password_helper,
            security=UserManagerSecurity[UUID](
                verification_token_secret=verification_token_secret,
                reset_password_token_secret=reset_password_token_secret,
                id_parser=id_parser,
            ),
            backends=backends,
        )
        self.forgot_password_events: list[tuple[ExampleUser, str]] = []

    async def on_after_forgot_password(self, user: ExampleUser | None, token: str | None) -> None:
        """Record each generated reset-password token."""
        if user is not None and token is not None:
            self.forgot_password_events.append((user, token))


class InMemoryTokenStrategy(Strategy[ExampleUser, UUID]):
    """Stateful test strategy used to verify backend-specific auth routes."""

    def __init__(self, *, token_prefix: str) -> None:
        """Initialize token storage for a specific backend."""
        self.token_prefix = token_prefix
        self.tokens: dict[str, UUID] = {}
        self.counter = 0

    async def read_token(
        self,
        token: str | None,
        user_manager: UserManagerProtocol[ExampleUser, UUID],
    ) -> ExampleUser | None:
        """Resolve a user from the in-memory token store.

        Returns:
            The matching user when a token is present and valid.
        """
        if token is None:
            return None

        user_id = self.tokens.get(token)
        if user_id is None:
            return None

        return await user_manager.get(user_id)

    async def write_token(self, user: ExampleUser) -> str:
        """Persist and return a deterministic test token.

        Returns:
            The issued token value.
        """
        self.counter += 1
        token = f"{self.token_prefix}-{self.counter}"
        self.tokens[token] = user.id
        return token

    async def destroy_token(self, token: str, user: ExampleUser) -> None:
        """Remove a token from storage."""
        del user
        self.tokens.pop(token, None)


class InMemoryRefreshTokenStrategy(InMemoryTokenStrategy):
    """Test strategy that supports refresh-token rotation."""

    def __init__(self, *, token_prefix: str) -> None:
        """Initialize refresh-token storage alongside access tokens."""
        super().__init__(token_prefix=token_prefix)
        self.refresh_tokens: dict[str, UUID] = {}
        self.refresh_counter = 0

    async def write_refresh_token(self, user: ExampleUser) -> str:
        """Issue and store a deterministic refresh token.

        Returns:
            The stored refresh token value.
        """
        self.refresh_counter += 1
        token = f"{self.token_prefix}-refresh-{self.refresh_counter}"
        self.refresh_tokens[token] = user.id
        return token

    async def rotate_refresh_token(
        self,
        refresh_token: str,
        user_manager: UserManagerProtocol[ExampleUser, UUID],
    ) -> tuple[ExampleUser, str] | None:
        """Consume a refresh token and replace it with a new one.

        Returns:
            The resolved user plus a rotated refresh token, or ``None``.
        """
        user_id = self.refresh_tokens.pop(refresh_token, None)
        if user_id is None:
            return None

        user = await user_manager.get(user_id)
        if user is None:
            return None

        return user, await self.write_refresh_token(user)


class DummySession:
    """Placeholder session (async context manager + ``close`` like ``AsyncSession``)."""

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
        """No-op close for ``before_send`` handlers."""

    async def commit(self) -> None:
        """No-op commit for lifecycle parity."""

    async def rollback(self) -> None:
        """No-op rollback for lifecycle parity."""


class DummySessionMaker:
    """Callable session factory compatible with scoped session wiring (mirrors ``async_sessionmaker``)."""

    def __call__(self) -> DummySession:
        """Return a fresh dummy session."""
        return DummySession()


@get("/dependency-probe", sync_to_thread=False)
def dependency_probe(
    litestar_auth_user_manager: object,
    litestar_auth_config: object,
) -> dict[str, bool]:
    """Expose whether the plugin registered DI providers.

    Returns:
        Booleans describing dependency availability.
    """
    return {
        "has_user_manager": litestar_auth_user_manager is not None,
        "has_config": litestar_auth_config is not None,
    }


@get("/auth-state", sync_to_thread=False)
def auth_state(request: Request[Any, Any, Any]) -> dict[str, str | None]:
    """Expose the authenticated email for middleware assertions.

    Returns:
        The authenticated email when a user is present.
    """
    user = cast("ExampleUser | None", request.user)
    return {"email": user.email if user is not None else None}


@get("/non-auth-client-exception", sync_to_thread=False)
def non_auth_client_exception() -> None:
    """Raise a non-auth ClientException for handler-scoping regressions.

    Raises:
        ClientException: Always, to verify the plugin no longer intercepts unrelated routes.
    """
    raise ClientException(
        status_code=HTTP_BAD_REQUEST,
        detail="Outside auth routes.",
        extra={"code": "NON_AUTH_ROUTE"},
    )


def build_app() -> tuple[
    Litestar,
    InMemoryUserDatabase,
    InMemoryTokenStrategy,
    InMemoryTokenStrategy,
]:
    """Create an app configured through the auth plugin.

    Returns:
        The Litestar app, shared user DB, and backend token strategies.
    """
    password_helper = PasswordHelper()
    admin_user = ExampleUser(
        id=uuid4(),
        email="admin@example.com",
        hashed_password=password_helper.hash("admin-password"),
        is_superuser=True,
        is_verified=True,
    )
    regular_user = ExampleUser(
        id=uuid4(),
        email="user@example.com",
        hashed_password=password_helper.hash("user-password"),
        is_verified=True,
    )
    user_db = InMemoryUserDatabase([admin_user, regular_user])
    verify_secret = "verify-secret-12345678901234567890"
    reset_secret = "reset-secret-123456789012345678901"
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
    config = LitestarAuthConfig[ExampleUser, UUID](
        backends=backends,
        session_maker=cast("Any", DummySessionMaker()),
        user_model=ExampleUser,
        user_manager_class=PluginUserManager,
        user_db_factory=lambda _session: user_db,
        user_manager_security=UserManagerSecurity[UUID](
            verification_token_secret=verify_secret,
            reset_password_token_secret=reset_secret,
            id_parser=UUID,
            password_helper=password_helper,
        ),
        include_users=True,
    )
    plugin = LitestarAuth(config)
    app = Litestar(route_handlers=[dependency_probe, auth_state, non_auth_client_exception], plugins=[plugin])
    return app, user_db, primary_strategy, secondary_strategy


def build_app_with_security_overrides(
    extra_security_overrides: dict[str, Any],
) -> tuple[Litestar, InMemoryUserDatabase, InMemoryTokenStrategy, InMemoryTokenStrategy]:
    """Create an app configured through the auth plugin with manager overrides.

    Returns:
        App plus the shared in-memory database and backend token strategies.
    """
    password_helper = PasswordHelper()
    admin_user = ExampleUser(
        id=uuid4(),
        email="admin@example.com",
        hashed_password=password_helper.hash("admin-password"),
        is_superuser=True,
        is_verified=True,
    )
    regular_user = ExampleUser(
        id=uuid4(),
        email="user@example.com",
        hashed_password=password_helper.hash("user-password"),
        is_verified=True,
    )
    user_db = InMemoryUserDatabase([admin_user, regular_user])
    verify_secret = "verify-secret-12345678901234567890"
    reset_secret = "reset-secret-123456789012345678901"
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
    config = LitestarAuthConfig[ExampleUser, UUID](
        backends=backends,
        session_maker=cast("Any", DummySessionMaker()),
        user_model=ExampleUser,
        user_manager_class=PluginUserManager,
        user_db_factory=lambda _session: user_db,
        user_manager_security=UserManagerSecurity[UUID](
            verification_token_secret=verify_secret,
            reset_password_token_secret=reset_secret,
            id_parser=UUID,
            password_helper=password_helper,
            **extra_security_overrides,
        ),
        include_users=True,
    )
    plugin = LitestarAuth(config)
    app = Litestar(route_handlers=[dependency_probe, auth_state], plugins=[plugin])
    return app, user_db, primary_strategy, secondary_strategy


class PluginUserCreate(msgspec.Struct):
    """Custom registration schema used to verify plugin DTO passthrough."""

    email: str
    password: str
    bio: str


class PluginUserRead(msgspec.Struct):
    """Custom read schema used to verify plugin DTO passthrough."""

    id: UUID
    email: str
    is_active: bool
    is_verified: bool
    is_superuser: bool
    bio: str


class PluginUserUpdate(msgspec.Struct, omit_defaults=True):
    """Custom update schema used to verify plugin DTO passthrough."""

    email: str | None = None
    password: str | None = None
    bio: str | None = None


def build_advanced_app() -> tuple[
    Litestar,
    InMemoryUserDatabase,
    InMemoryRefreshTokenStrategy,
    InMemoryUsedTotpCodeStore,
]:
    """Create an app that exercises advanced plugin configuration options.

    Returns:
        The Litestar app, backing in-memory DB, refresh-capable strategy, and TOTP replay store.
    """
    password_helper = PasswordHelper()
    admin_user = ExampleUser(
        id=uuid4(),
        email="admin@example.com",
        hashed_password=password_helper.hash("admin-password"),
        is_superuser=True,
        is_verified=True,
    )
    user_with_totp = ExampleUser(
        id=uuid4(),
        email="user@example.com",
        hashed_password=password_helper.hash("user-password"),
        is_verified=True,
    )
    user_db = InMemoryUserDatabase([admin_user, user_with_totp])
    strategy = InMemoryRefreshTokenStrategy(token_prefix="plugin")
    used_tokens_store = InMemoryUsedTotpCodeStore()
    backend = AuthenticationBackend[ExampleUser, UUID](
        name="primary",
        transport=BearerTransport(),
        strategy=cast("Any", strategy),
    )
    config = LitestarAuthConfig[ExampleUser, UUID](
        backends=[backend],
        session_maker=cast("Any", DummySessionMaker()),
        user_model=ExampleUser,
        user_manager_class=PluginUserManager,
        user_db_factory=lambda _session: user_db,
        user_manager_security=UserManagerSecurity[UUID](
            verification_token_secret="verify-secret-12345678901234567890",
            reset_password_token_secret="reset-secret-123456789012345678901",
            totp_secret_key=Fernet.generate_key().decode(),
            id_parser=UUID,
            password_helper=password_helper,
        ),
        include_users=True,
        totp_config=TotpConfig(
            totp_pending_secret="plugin-totp-pending-secret-thirty-two!",
            totp_pending_jti_store=InMemoryJWTDenylistStore(),
            totp_used_tokens_store=used_tokens_store,
        ),
        enable_refresh=True,
        hard_delete=True,
        user_read_schema=PluginUserRead,
        user_create_schema=PluginUserCreate,
        user_update_schema=PluginUserUpdate,
    )
    plugin = LitestarAuth(config)
    app = Litestar(route_handlers=[dependency_probe, auth_state], plugins=[plugin])
    return app, user_db, strategy, used_tokens_store


@pytest.fixture
def app() -> tuple[
    Litestar,
    InMemoryUserDatabase,
    InMemoryTokenStrategy,
    InMemoryTokenStrategy,
]:
    """Create the shared plugin app and collaborators.

    Returns:
        App plus the shared in-memory database and backend strategies.
    """
    return build_app()


def test_plugin_uses_dataclass_config_and_init_plugin_protocol() -> None:
    """The orchestrator exposes a dataclass config and Litestar init plugin."""
    invalid_config = LitestarAuthConfig[ExampleUser, UUID](
        backends=[],
        session_maker=cast("Any", DummySessionMaker()),
        user_model=ExampleUser,
        user_manager_class=PluginUserManager,
        user_manager_security=UserManagerSecurity[UUID](password_helper=PasswordHelper()),
    )

    assert is_dataclass(invalid_config)
    with pytest.raises(ValueError, match="at least one authentication backend"):
        LitestarAuth(invalid_config)

    app, user_db, primary_strategy, secondary_strategy = build_app()
    del app, user_db, primary_strategy, secondary_strategy

    valid_config = LitestarAuthConfig[ExampleUser, UUID](
        backends=[
            AuthenticationBackend[ExampleUser, UUID](
                name="primary",
                transport=BearerTransport(),
                strategy=cast("Any", InMemoryTokenStrategy(token_prefix="plugin")),
            ),
        ],
        session_maker=cast("Any", DummySessionMaker()),
        user_model=ExampleUser,
        user_manager_class=PluginUserManager,
        user_db_factory=lambda _session: InMemoryUserDatabase([]),
        user_manager_security=UserManagerSecurity[UUID](password_helper=PasswordHelper()),
    )
    assert isinstance(LitestarAuth(valid_config), InitPlugin)


async def test_plugin_registers_di_middleware_and_generated_controllers(
    client: tuple[
        AsyncTestClient[Litestar],
        InMemoryUserDatabase,
        InMemoryTokenStrategy,
        InMemoryTokenStrategy,
    ],
) -> None:
    """The plugin wires DI, middleware, and controller routes into the app."""
    test_client, user_db, primary_strategy, secondary_strategy = client
    app = test_client.app

    assert "litestar_auth_user_manager" in app.dependencies
    assert "litestar_auth_config" in app.dependencies
    assert "db_session" in app.dependencies
    assert any(middleware.middleware.__name__ == "LitestarAuthMiddleware" for middleware in app.middleware)

    dependency_response = await test_client.get("/dependency-probe")
    assert dependency_response.status_code == HTTP_OK
    assert dependency_response.json() == {"has_user_manager": True, "has_config": True}

    register_response = await test_client.post(
        "/auth/register",
        json={"email": "fresh@example.com", "password": "fresh-password"},
    )
    assert register_response.status_code == HTTP_CREATED
    assert user_db.user_ids_by_email["fresh@example.com"] in user_db.users_by_id

    verify_request_response = await test_client.post(
        "/auth/request-verify-token",
        json={"email": "fresh@example.com"},
    )
    assert verify_request_response.status_code == HTTP_ACCEPTED

    forgot_password_response = await test_client.post(
        "/auth/forgot-password",
        json={"email": "fresh@example.com"},
    )
    assert forgot_password_response.status_code == HTTP_ACCEPTED

    primary_login_response = await test_client.post(
        "/auth/login",
        json={"identifier": "user@example.com", "password": "user-password"},
    )
    assert primary_login_response.status_code == HTTP_CREATED
    assert primary_login_response.json() == {"access_token": "primary-1", "token_type": "bearer"}
    assert list(primary_strategy.tokens) == ["primary-1"]

    secondary_login_response = await test_client.post(
        "/auth/secondary/login",
        json={"identifier": "user@example.com", "password": "user-password"},
    )
    assert secondary_login_response.status_code == HTTP_CREATED
    assert secondary_login_response.json() == {"access_token": "secondary-1", "token_type": "bearer"}
    assert list(secondary_strategy.tokens) == ["secondary-1"]

    me_response = await test_client.get("/users/me", headers={"Authorization": "Bearer primary-1"})
    assert me_response.status_code == HTTP_OK
    assert me_response.json()["email"] == "user@example.com"

    auth_state_response = await test_client.get("/auth-state", headers={"Authorization": "Bearer primary-1"})
    assert auth_state_response.status_code == HTTP_OK
    assert auth_state_response.json() == {"email": "user@example.com"}

    admin_login_response = await test_client.post(
        "/auth/login",
        json={"identifier": "admin@example.com", "password": "admin-password"},
    )
    assert admin_login_response.status_code == HTTP_CREATED
    assert admin_login_response.json() == {"access_token": "primary-2", "token_type": "bearer"}

    users_response = await test_client.get("/users", headers={"Authorization": "Bearer primary-2"})
    assert users_response.status_code == HTTP_OK
    assert users_response.json()["total"] == TOTAL_USERS


async def test_plugin_scopes_client_exception_handler_to_auth_routes() -> None:
    """Plugin-owned auth routes keep auth error formatting without affecting unrelated routes."""
    app, _user_db, _primary_strategy, _secondary_strategy = build_app()

    async with AsyncTestClient(app=app) as client:
        auth_response = await client.post("/auth/verify", json={"token": "not-a-valid-token"})
        non_auth_response = await client.get("/non-auth-client-exception")

    assert auth_response.status_code == HTTP_BAD_REQUEST
    assert auth_response.json() == {
        "detail": "The email verification token is invalid.",
        "code": ErrorCode.VERIFY_USER_BAD_TOKEN,
    }

    assert non_auth_response.status_code == HTTP_BAD_REQUEST
    assert non_auth_response.json()["status_code"] == HTTP_BAD_REQUEST
    assert non_auth_response.json()["detail"] == "Outside auth routes."
    assert non_auth_response.json().get("code") is None
    assert non_auth_response.json()["extra"]["code"] == "NON_AUTH_ROUTE"


async def test_plugin_enforces_default_minimum_password_length() -> None:
    """The plugin defaults to rejecting passwords shorter than 12 characters."""
    app, _user_db, _primary_strategy, _secondary_strategy = build_app()
    async with AsyncTestClient(app=app) as client:
        too_short_response = await client.post(
            "/auth/register",
            json={"email": "short@example.com", "password": "12345678"},
        )
        assert too_short_response.status_code == HTTP_UNPROCESSABLE_ENTITY

        ok_response = await client.post(
            "/auth/register",
            json={"email": "ok@example.com", "password": "123456789012"},
        )
        assert ok_response.status_code == HTTP_CREATED


async def test_plugin_allows_overriding_minimum_password_length() -> None:
    """Applications can override the default password validator via config."""
    app, user_db, primary_strategy, secondary_strategy = build_app_with_security_overrides(
        {"password_validator": partial(require_password_length, minimum_length=8)},
    )
    async with AsyncTestClient(app=app) as client:
        response = await client.post(
            "/auth/register",
            json={"email": "override@example.com", "password": "123456789012"},
        )
        assert response.status_code == HTTP_CREATED

    del user_db, primary_strategy, secondary_strategy


@pytest.mark.filterwarnings("ignore::litestar_auth.totp.SecurityWarning")
async def test_plugin_passes_advanced_controller_options_through_config(monkeypatch: pytest.MonkeyPatch) -> None:
    """Advanced controller options remain available when the plugin generates routes."""
    monkeypatch.setattr("litestar_auth.totp.time.time", lambda: 59.0)
    app, user_db, strategy, used_tokens_store = build_advanced_app()
    helper_manager = TokenCaptureUserManager(
        user_db,
        password_helper=PasswordHelper(),
        verification_token_secret="verify-secret-12345678901234567890",
        reset_password_token_secret="reset-secret-123456789012345678901",
        id_parser=UUID,
    )

    async with AsyncTestClient(app=app) as client:
        register_response = await client.post(
            "/auth/register",
            json={"email": "schema@example.com", "password": "schema-password", "bio": "Schema via plugin"},
        )
        assert register_response.status_code == HTTP_CREATED
        assert not register_response.json()["bio"]

        created_user = await user_db.get_by_email("schema@example.com")
        assert created_user is not None
        verify_token = helper_manager.write_verify_token(created_user)
        verify_response = await client.post("/auth/verify", json={"token": verify_token})
        assert verify_response.status_code == HTTP_OK
        assert not verify_response.json()["bio"]

        await helper_manager.forgot_password(created_user.email)
        _, reset_token = helper_manager.forgot_password_events[0]
        reset_response = await client.post(
            "/auth/reset-password",
            json={"token": reset_token, "password": "updated-password"},
        )
        assert reset_response.status_code == HTTP_OK
        assert not reset_response.json()["bio"]

        deleted_user = await _register_update_and_delete_user(client, user_db, strategy)
        await _verify_totp_replay_protection(client, user_db, used_tokens_store)
        assert await user_db.get(deleted_user.id) is None


async def _register_update_and_delete_user(
    client: AsyncTestClient[Litestar],
    user_db: InMemoryUserDatabase,
    strategy: InMemoryRefreshTokenStrategy,
) -> ExampleUser:
    """Exercise plugin-managed DTOs, refresh tokens, and hard delete.

    Returns:
        The user created through the custom registration schema.
    """
    register_response = await client.post(
        "/auth/register",
        json={"email": "fresh@example.com", "password": "fresh-password", "bio": "Created via plugin"},
    )
    assert register_response.status_code == HTTP_CREATED
    assert not register_response.json()["bio"]

    created_user = await user_db.get_by_email("fresh@example.com")
    assert created_user is not None
    assert not created_user.bio

    login_response = await client.post(
        "/auth/login",
        json={"identifier": "admin@example.com", "password": "admin-password"},
    )
    assert login_response.status_code == HTTP_CREATED
    assert login_response.json() == {
        "access_token": "plugin-1",
        "token_type": "bearer",
        "refresh_token": "plugin-refresh-1",
    }

    refresh_response = await client.post("/auth/refresh", json={"refresh_token": "plugin-refresh-1"})
    assert refresh_response.status_code == HTTP_CREATED
    assert refresh_response.json() == {
        "access_token": "plugin-2",
        "token_type": "bearer",
        "refresh_token": "plugin-refresh-2",
    }
    assert "plugin-refresh-1" not in strategy.refresh_tokens

    update_response = await client.patch(
        "/users/me",
        headers={"Authorization": "Bearer plugin-2"},
        json={"bio": "Updated via plugin"},
    )
    assert update_response.status_code == HTTP_OK
    assert update_response.json()["bio"] == "Updated via plugin"
    assert not created_user.bio

    delete_response = await client.delete(
        f"/users/{created_user.id}",
        headers={"Authorization": "Bearer plugin-2"},
    )
    assert delete_response.status_code == HTTP_OK
    assert not delete_response.json()["bio"]
    return created_user


async def _verify_totp_replay_protection(
    client: AsyncTestClient[Litestar],
    user_db: InMemoryUserDatabase,
    used_tokens_store: InMemoryUsedTotpCodeStore,
) -> None:
    """Exercise plugin-managed TOTP routes with replay protection enabled."""
    login_headers = {"Authorization": "Bearer plugin-2"}
    enable_response = await client.post(
        "/auth/2fa/enable",
        json={"password": "admin-password"},
        headers=login_headers,
    )
    assert enable_response.status_code == HTTP_CREATED
    enable_body = enable_response.json()
    secret = enable_body["secret"]

    confirm_code = _generate_totp_code(secret, _totp_mod._current_counter())
    confirm_response = await client.post(
        "/auth/2fa/enable/confirm",
        json={"enrollment_token": enable_body["enrollment_token"], "code": confirm_code},
        headers=login_headers,
    )
    assert confirm_response.status_code == HTTP_CREATED

    admin_user = await user_db.get_by_email("admin@example.com")
    assert admin_user is not None
    code = _generate_totp_code(secret, _totp_mod._current_counter())

    pending_response = await client.post(
        "/auth/login",
        json={"identifier": "admin@example.com", "password": "admin-password"},
    )
    assert pending_response.status_code == HTTP_ACCEPTED
    pending_token = pending_response.json()["pending_token"]

    verify_response = await client.post("/auth/2fa/verify", json={"pending_token": pending_token, "code": code})
    assert verify_response.status_code == HTTP_CREATED
    assert verify_response.json() == {"access_token": "plugin-3", "token_type": "bearer"}

    replay_response = await client.post("/auth/2fa/verify", json={"pending_token": pending_token, "code": code})
    assert replay_response.status_code == HTTP_BAD_REQUEST
    assert replay_response.json()["detail"] == INVALID_TOTP_TOKEN_DETAIL
    replay_mark = await used_tokens_store.mark_used(admin_user.id, _current_counter(), 60.0)
    assert replay_mark.stored is False
    assert replay_mark.rejected_as_replay is True
