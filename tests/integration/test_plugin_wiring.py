"""Integration tests for auth plugin wiring and configuration behavior."""

from __future__ import annotations

from typing import TYPE_CHECKING, Any, cast
from uuid import UUID, uuid4

import pytest
from cryptography.fernet import Fernet
from litestar import Litestar, get
from litestar.config.app import AppConfig
from litestar.config.csrf import CSRFConfig
from litestar.di import Provide
from litestar.testing import AsyncTestClient

from litestar_auth._plugin import (
    DEFAULT_BACKENDS_DEPENDENCY_KEY,
    DEFAULT_CONFIG_DEPENDENCY_KEY,
    DEFAULT_CSRF_COOKIE_NAME,
    DEFAULT_USER_MANAGER_DEPENDENCY_KEY,
    DEFAULT_USER_MODEL_DEPENDENCY_KEY,
    OAUTH_ASSOCIATE_USER_MANAGER_DEPENDENCY_KEY,
)
from litestar_auth._plugin.config import OAuthConfig, TotpConfig
from litestar_auth.authentication.backend import AuthenticationBackend
from litestar_auth.authentication.transport.bearer import BearerTransport
from litestar_auth.authentication.transport.cookie import CookieTransport
from litestar_auth.exceptions import ConfigurationError
from litestar_auth.password import PasswordHelper
from litestar_auth.plugin import LitestarAuth, LitestarAuthConfig

from .test_orchestrator import (
    DummySessionMaker,
    ExampleUser,
    InMemoryTokenStrategy,
    InMemoryUserDatabase,
    PluginUserManager,
)

if TYPE_CHECKING:
    from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

    from litestar_auth.manager import BaseUserManager

pytestmark = pytest.mark.integration
HTTP_OK = 200
HTTP_CREATED = 201
HTTP_NOT_FOUND = 404


def _minimal_litestar_auth_config(
    *,
    backends: list[AuthenticationBackend[ExampleUser, UUID]] | None = None,
) -> LitestarAuthConfig[ExampleUser, UUID]:
    user_db = InMemoryUserDatabase([])
    strategies = backends or [
        AuthenticationBackend[ExampleUser, UUID](
            name="primary",
            transport=BearerTransport(),
            strategy=cast("Any", InMemoryTokenStrategy(token_prefix="plugin-wiring")),
        ),
    ]
    return LitestarAuthConfig[ExampleUser, UUID](
        backends=strategies,
        session_maker=cast("async_sessionmaker[AsyncSession]", DummySessionMaker()),
        user_model=ExampleUser,
        user_manager_class=PluginUserManager,
        user_db_factory=lambda _session: user_db,
        user_manager_kwargs={
            "verification_token_secret": "verify-secret-12345678901234567890",
            "reset_password_token_secret": "reset-secret-123456789012345678901",
            "id_parser": UUID,
        },
        include_users=False,
        totp_config=None,
    )


class _DummyAsyncSession:
    """Placeholder async session object used for session-bound backend tests."""


def test_build_user_manager_yields_distinct_managers_per_session() -> None:
    """Each request-local session gets its own user manager instance."""
    config = _minimal_litestar_auth_config()
    plugin = LitestarAuth(config)
    first_session = _DummyAsyncSession()
    second_session = _DummyAsyncSession()

    first_manager = plugin._build_user_manager(cast("Any", first_session))
    second_manager = plugin._build_user_manager(cast("Any", second_session))

    assert first_manager is not second_manager


def test_dependency_collision_raises_value_error() -> None:
    """on_app_init detects dependency key collisions and raises ValueError."""
    config = _minimal_litestar_auth_config()
    plugin = LitestarAuth(config)
    app_config = AppConfig()
    collision_key = DEFAULT_CONFIG_DEPENDENCY_KEY
    app_config.dependencies[collision_key] = Provide(lambda: None, sync_to_thread=False)

    with pytest.raises(ValueError, match=collision_key):
        plugin.on_app_init(app_config)


def test_cookie_transport_registers_litestar_csrf_config() -> None:
    """Cookie transports cause the plugin to configure Litestar's CSRF support."""
    backend = AuthenticationBackend[ExampleUser, UUID](
        name="cookie",
        transport=CookieTransport(cookie_name="custom_auth", path="/auth", secure=False, samesite="strict"),
        strategy=cast("Any", InMemoryTokenStrategy(token_prefix="csrf-wiring")),
    )
    config = _minimal_litestar_auth_config(backends=[backend])
    config.csrf_secret = "c" * 32
    plugin = LitestarAuth(config)
    app_config = AppConfig()

    result = plugin.on_app_init(app_config)

    assert isinstance(result.csrf_config, CSRFConfig)
    assert result.csrf_config.cookie_name == DEFAULT_CSRF_COOKIE_NAME
    assert result.csrf_config.cookie_path == "/auth"
    assert result.csrf_config.cookie_secure is False
    assert result.csrf_config.cookie_samesite == "strict"
    assert result.csrf_config.header_name == "X-CSRF-Token"


def test_validate_config_include_users_requires_list_users() -> None:
    """include_users=True with a manager lacking list_users fails validation."""
    user_db = InMemoryUserDatabase([])

    class _UserManagerWithoutListUsers:  # pragma: no cover - shape-only for validation
        def __init__(self, *_: object, **__: object) -> None:
            """Accept arbitrary arguments without behavior."""

    config = LitestarAuthConfig[ExampleUser, UUID](
        backends=_minimal_litestar_auth_config().backends,
        session_maker=cast("async_sessionmaker[AsyncSession]", DummySessionMaker()),
        user_model=ExampleUser,
        user_manager_class=cast("type[BaseUserManager[ExampleUser, UUID]]", _UserManagerWithoutListUsers),
        user_db_factory=lambda _session: user_db,
        user_manager_kwargs={},
        include_users=True,
    )

    with pytest.raises(ValueError, match="list_users"):
        LitestarAuth(config)


def test_validate_config_totp_config_requires_pending_secret() -> None:
    """totp_config requires a non-empty totp_pending_secret."""
    config = _minimal_litestar_auth_config()
    config.totp_config = TotpConfig(totp_pending_secret="")

    with pytest.raises(ValueError, match="totp_pending_secret"):
        LitestarAuth(config)


async def test_plugin_propagates_login_identifier_username_to_auth_login() -> None:
    """LitestarAuthConfig.login_identifier=username is honored for /auth/login lookup."""
    password_helper = PasswordHelper()
    user = ExampleUser(
        id=uuid4(),
        email="u@example.com",
        username="pluginuser",
        hashed_password=password_helper.hash("correct-password"),
        is_verified=True,
    )
    user_db = InMemoryUserDatabase([user])
    backend = AuthenticationBackend[ExampleUser, UUID](
        name="primary",
        transport=BearerTransport(),
        strategy=cast("Any", InMemoryTokenStrategy(token_prefix="username-login")),
    )
    config = LitestarAuthConfig[ExampleUser, UUID](
        backends=[backend],
        session_maker=cast("async_sessionmaker[AsyncSession]", DummySessionMaker()),
        user_model=ExampleUser,
        user_manager_class=PluginUserManager,
        user_db_factory=lambda _session: user_db,
        user_manager_kwargs={
            "password_helper": password_helper,
            "verification_token_secret": "verify-secret-12345678901234567890",
            "reset_password_token_secret": "reset-secret-123456789012345678901",
            "id_parser": UUID,
        },
        include_register=False,
        include_verify=False,
        include_reset_password=False,
        include_users=False,
        login_identifier="username",
    )
    app = Litestar(plugins=[LitestarAuth(config)])
    async with AsyncTestClient(app=app) as client:
        response = await client.post(
            "/auth/login",
            json={"identifier": "pluginuser", "password": "correct-password"},
        )
        assert response.status_code == HTTP_CREATED
        assert "access_token" in response.json()


def test_oauth_associate_dependency_registered_when_enabled() -> None:
    """OAuth associate user-manager dependency is registered when configured."""
    provider = ("example", object())
    config = _minimal_litestar_auth_config()
    config.oauth_config = OAuthConfig(
        include_oauth_associate=True,
        oauth_associate_providers=[provider],
        oauth_token_encryption_key="a" * 44,
    )
    plugin = LitestarAuth(config)
    app_config = AppConfig()

    result_config = plugin.on_app_init(app_config)

    assert OAUTH_ASSOCIATE_USER_MANAGER_DEPENDENCY_KEY in result_config.dependencies


def test_oauth_associate_requires_encryption_key_at_startup() -> None:
    """OAuth associate startup fails closed when token encryption is not configured."""
    config = _minimal_litestar_auth_config()
    config.oauth_config = OAuthConfig(
        include_oauth_associate=True,
        oauth_associate_providers=[("example", object())],
    )
    plugin = LitestarAuth(config)

    with pytest.raises(ConfigurationError, match=r"oauth_token_encryption_key is required"):
        plugin.on_app_init(AppConfig())


async def test_plugin_respects_public_mount_paths_and_dependency_keys() -> None:
    """Public path values and default internal DI keys remain stable."""

    @get("/contract-probe", sync_to_thread=False)
    def contract_probe(
        litestar_auth_config: object,
        litestar_auth_user_manager: object,
        litestar_auth_backends: object,
        litestar_auth_user_model: object,
    ) -> dict[str, bool]:
        return {
            "has_config": litestar_auth_config is not None,
            "has_manager": litestar_auth_user_manager is not None,
            "has_backends": litestar_auth_backends is not None,
            "has_user_model": litestar_auth_user_model is ExampleUser,
        }

    @get("/di-session-probe", sync_to_thread=False)
    def di_session_probe(
        db_session: object,
        litestar_auth_user_manager: object,
    ) -> dict[str, bool]:
        """Assert user_manager DI is wired to the same db_session key as the plugin.

        Returns:
            Flags indicating both dependencies resolved for the request.
        """
        return {
            "has_session": db_session is not None,
            "has_manager": litestar_auth_user_manager is not None,
        }

    password_helper = PasswordHelper()
    user = ExampleUser(
        id=UUID(int=1),
        email="public@example.com",
        hashed_password=password_helper.hash("correct-password"),
        is_verified=True,
    )
    user_db = InMemoryUserDatabase([user])
    backend = AuthenticationBackend[ExampleUser, UUID](
        name="primary",
        transport=BearerTransport(),
        strategy=cast("Any", InMemoryTokenStrategy(token_prefix="public-contract")),
    )
    config = LitestarAuthConfig[ExampleUser, UUID](
        backends=[backend],
        session_maker=cast("async_sessionmaker[AsyncSession]", DummySessionMaker()),
        user_model=ExampleUser,
        user_manager_class=PluginUserManager,
        user_db_factory=lambda _session: user_db,
        user_manager_kwargs={
            "password_helper": password_helper,
            "verification_token_secret": "verify-secret-12345678901234567890",
            "reset_password_token_secret": "reset-secret-123456789012345678901",
            "id_parser": UUID,
        },
        auth_path="/api/account",
        users_path="/api/members",
        include_users=True,
    )
    app = Litestar(route_handlers=[contract_probe, di_session_probe], plugins=[LitestarAuth(config)])

    assert DEFAULT_CONFIG_DEPENDENCY_KEY in app.dependencies
    assert DEFAULT_USER_MANAGER_DEPENDENCY_KEY in app.dependencies
    assert DEFAULT_BACKENDS_DEPENDENCY_KEY in app.dependencies
    assert DEFAULT_USER_MODEL_DEPENDENCY_KEY in app.dependencies
    assert "db_session" in app.dependencies

    async with AsyncTestClient(app=app) as client:
        probe_response = await client.get("/contract-probe")
        assert probe_response.status_code == HTTP_OK
        assert probe_response.json() == {
            "has_config": True,
            "has_manager": True,
            "has_backends": True,
            "has_user_model": True,
        }

        di_session_response = await client.get("/di-session-probe")
        assert di_session_response.status_code == HTTP_OK
        assert di_session_response.json() == {
            "has_session": True,
            "has_manager": True,
        }

        login_response = await client.post(
            "/api/account/login",
            json={"identifier": "public@example.com", "password": "correct-password"},
        )
        assert login_response.status_code == HTTP_CREATED
        access_token = login_response.json()["access_token"]

        me_response = await client.get(
            "/api/members/me",
            headers={"Authorization": f"Bearer {access_token}"},
        )
        assert me_response.status_code == HTTP_OK
        assert me_response.json()["email"] == "public@example.com"

        default_auth_path_response = await client.post(
            "/auth/login",
            json={"identifier": "public@example.com", "password": "correct-password"},
        )
        assert default_auth_path_response.status_code == HTTP_NOT_FOUND

        default_users_path_response = await client.get(
            "/users/me",
            headers={"Authorization": f"Bearer {access_token}"},
        )
        assert default_users_path_response.status_code == HTTP_NOT_FOUND


def test_session_bound_backends_applies_with_session_to_strategies() -> None:
    """Plugin binds SessionBindable strategies when assembling request-scoped backends."""

    class StrategyWithSession(InMemoryTokenStrategy):
        def __init__(self) -> None:
            super().__init__(token_prefix="session-bound")
            self.sessions_seen: list[object] = []

        def with_session(self, session: object) -> InMemoryTokenStrategy:
            self.sessions_seen.append(session)
            return self

    strategy = StrategyWithSession()
    backend = AuthenticationBackend[ExampleUser, UUID](
        name="primary",
        transport=BearerTransport(),
        strategy=cast("Any", strategy),
    )
    config = _minimal_litestar_auth_config(backends=[backend])
    plugin = LitestarAuth(config)
    dummy_session = _DummyAsyncSession()

    bound_backends = plugin._session_bound_backends(cast("Any", dummy_session))

    assert len(bound_backends) == 1
    assert bound_backends[0] is backend
    assert strategy.sessions_seen == [dummy_session]


def test_totp_backend_resolves_named_backend() -> None:
    """_totp_backend returns the backend matching the configured name."""
    primary_strategy = InMemoryTokenStrategy(token_prefix="primary")
    secondary_strategy = InMemoryTokenStrategy(token_prefix="secondary")
    primary_backend = AuthenticationBackend[ExampleUser, UUID](
        name="primary",
        transport=BearerTransport(),
        strategy=cast("Any", primary_strategy),
    )
    secondary_backend = AuthenticationBackend[ExampleUser, UUID](
        name="secondary",
        transport=BearerTransport(),
        strategy=cast("Any", secondary_strategy),
    )
    config = _minimal_litestar_auth_config(backends=[primary_backend, secondary_backend])
    config.totp_config = TotpConfig(
        totp_pending_secret="pending-secret-for-totp-pending-jwt-secret-123",
        totp_backend_name="secondary",
        totp_used_tokens_store=cast("Any", object()),
    )
    config.user_manager_kwargs["totp_secret_key"] = Fernet.generate_key().decode()
    plugin = LitestarAuth(config)

    totp_backend = plugin._totp_backend()

    assert totp_backend is secondary_backend


def test_totp_backend_unknown_name_raises_value_error() -> None:
    """_totp_backend raises ValueError when the configured name is not found."""
    primary_strategy = InMemoryTokenStrategy(token_prefix="primary")
    backend = AuthenticationBackend[ExampleUser, UUID](
        name="primary",
        transport=BearerTransport(),
        strategy=cast("Any", primary_strategy),
    )
    config = _minimal_litestar_auth_config(backends=[backend])
    config.totp_config = TotpConfig(
        totp_pending_secret="pending-secret-for-totp-pending-jwt-secret-123",
        totp_backend_name="unknown-backend",
        totp_used_tokens_store=cast("Any", object()),
    )
    config.user_manager_kwargs["totp_secret_key"] = Fernet.generate_key().decode()
    plugin = LitestarAuth(config)

    with pytest.raises(ValueError, match="unknown-backend"):
        plugin._totp_backend()
