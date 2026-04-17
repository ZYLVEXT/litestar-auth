"""Integration tests for auth plugin wiring and configuration behavior."""

from __future__ import annotations

from typing import TYPE_CHECKING, Any, cast
from uuid import UUID, uuid4

import pytest
from advanced_alchemy.extensions.litestar import SQLAlchemyAsyncConfig
from cryptography.fernet import Fernet
from litestar import Litestar, get
from litestar.config.app import AppConfig
from litestar.config.csrf import CSRFConfig
from litestar.di import Provide
from litestar.openapi.config import OpenAPIConfig
from litestar.testing import AsyncTestClient
from sqlalchemy import create_engine
from sqlalchemy.pool import StaticPool

import litestar_auth.plugin as plugin_module
from litestar_auth._plugin import (
    DEFAULT_BACKENDS_DEPENDENCY_KEY,
    DEFAULT_CONFIG_DEPENDENCY_KEY,
    DEFAULT_CSRF_COOKIE_NAME,
    DEFAULT_USER_MANAGER_DEPENDENCY_KEY,
    DEFAULT_USER_MODEL_DEPENDENCY_KEY,
    OAUTH_ASSOCIATE_USER_MANAGER_DEPENDENCY_KEY,
)
from litestar_auth._plugin.config import DatabaseTokenAuthConfig, OAuthConfig, TotpConfig
from litestar_auth.authentication.backend import AuthenticationBackend
from litestar_auth.authentication.strategy.jwt import InMemoryJWTDenylistStore
from litestar_auth.authentication.transport.bearer import BearerTransport
from litestar_auth.authentication.transport.cookie import CookieTransport
from litestar_auth.exceptions import ConfigurationError
from litestar_auth.guards import is_authenticated
from litestar_auth.manager import UserManagerSecurity
from litestar_auth.password import PasswordHelper
from litestar_auth.plugin import LitestarAuth, LitestarAuthConfig
from tests.e2e.conftest import SessionMaker as E2ESessionMaker
from tests.e2e.conftest import assert_structural_session_factory

from .test_orchestrator import (
    DummySessionMaker,
    ExampleUser,
    InMemoryRefreshTokenStrategy,
    InMemoryTokenStrategy,
    InMemoryUserDatabase,
    PluginUserManager,
)

if TYPE_CHECKING:
    from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

    from litestar_auth.manager import BaseUserManager

pytestmark = [pytest.mark.integration]
HTTP_OK = 200
HTTP_CREATED = 201
HTTP_NOT_FOUND = 404


class _OpenAPIOAuthClient:
    """Minimal OAuth client contract for schema-only plugin tests."""

    async def get_authorization_url(self, redirect_uri: str, state: str, *, scope: str | None = None) -> str:
        del redirect_uri, state, scope
        return "https://provider.example/authorize"

    async def get_access_token(self, code: str, redirect_uri: str) -> dict[str, str]:
        del code, redirect_uri
        return {"access_token": "provider-access-token"}

    async def get_id_email(self, access_token: str) -> tuple[str, str]:
        del access_token
        return "provider-user", "oauth@example.com"


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
        session_maker=cast(
            "async_sessionmaker[AsyncSession]",
            assert_structural_session_factory(DummySessionMaker()),
        ),
        user_model=ExampleUser,
        user_manager_class=PluginUserManager,
        user_db_factory=lambda _session: user_db,
        user_manager_security=UserManagerSecurity[UUID](
            verification_token_secret="verify-secret-12345678901234567890",
            reset_password_token_secret="reset-secret-123456789012345678901",
            id_parser=UUID,
        ),
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
        session_maker=cast(
            "async_sessionmaker[AsyncSession]",
            assert_structural_session_factory(DummySessionMaker()),
        ),
        user_model=ExampleUser,
        user_manager_class=cast("type[BaseUserManager[ExampleUser, UUID]]", _UserManagerWithoutListUsers),
        user_db_factory=lambda _session: user_db,
        user_manager_security=UserManagerSecurity[UUID](),
        include_users=True,
    )

    with pytest.raises(ValueError, match="list_users"):
        LitestarAuth(config)


def test_validate_config_totp_config_requires_pending_secret() -> None:
    """totp_config requires a non-empty totp_pending_secret."""
    config = _minimal_litestar_auth_config()
    config.totp_config = TotpConfig(totp_pending_secret="")

    with pytest.raises(ConfigurationError, match="totp_pending_secret"):
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
        session_maker=cast(
            "async_sessionmaker[AsyncSession]",
            assert_structural_session_factory(DummySessionMaker()),
        ),
        user_model=ExampleUser,
        user_manager_class=PluginUserManager,
        user_db_factory=lambda _session: user_db,
        user_manager_security=UserManagerSecurity[UUID](
            verification_token_secret="verify-secret-12345678901234567890",
            reset_password_token_secret="reset-secret-123456789012345678901",
            id_parser=UUID,
            password_helper=password_helper,
        ),
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
        oauth_providers=[provider],
        include_oauth_associate=True,
        oauth_redirect_base_url="https://app.example.com/auth",
        oauth_token_encryption_key="YWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWE=",
    )
    plugin = LitestarAuth(config)
    app_config = AppConfig()

    result_config = plugin.on_app_init(app_config)

    assert OAUTH_ASSOCIATE_USER_MANAGER_DEPENDENCY_KEY in result_config.dependencies


def test_oauth_login_inventory_does_not_register_associate_dependency() -> None:
    """OAuth login-provider config alone does not register the associate-only DI key."""
    config = _minimal_litestar_auth_config()
    config.oauth_config = OAuthConfig(
        oauth_providers=[("example", object())],
        oauth_redirect_base_url="https://app.example.com/auth",
        oauth_token_encryption_key="YWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWE=",
    )
    plugin = LitestarAuth(config)

    result_config = plugin.on_app_init(AppConfig())

    assert OAUTH_ASSOCIATE_USER_MANAGER_DEPENDENCY_KEY not in result_config.dependencies


def test_oauth_plugin_routes_require_encryption_key_at_startup() -> None:
    """Plugin-owned OAuth startup fails closed when token encryption is not configured."""
    config = _minimal_litestar_auth_config()
    config.oauth_config = OAuthConfig(
        oauth_providers=[("example", object())],
        include_oauth_associate=True,
        oauth_redirect_base_url="https://app.example.com/auth",
    )
    plugin = LitestarAuth(config)

    with pytest.raises(ConfigurationError, match=r"oauth_token_encryption_key is required"):
        plugin.on_app_init(AppConfig())


@pytest.mark.parametrize(
    ("redirect_base_url", "message"),
    [
        pytest.param(
            "http://app.example.com/auth",
            "public HTTPS origin",
            id="public-http-origin",
        ),
        pytest.param(
            "https://localhost/auth",
            "non-loopback public HTTPS origin",
            id="loopback-https-origin",
        ),
    ],
)
def test_oauth_plugin_routes_require_secure_public_redirect_origins_at_startup(
    redirect_base_url: str,
    message: str,
) -> None:
    """Plugin-owned OAuth startup now fails closed for insecure redirect origins."""
    config = _minimal_litestar_auth_config()
    config.oauth_config = OAuthConfig(
        oauth_providers=[("example", object())],
        oauth_redirect_base_url=redirect_base_url,
        oauth_token_encryption_key="YWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWE=",
    )
    plugin = LitestarAuth(config)

    with pytest.raises(ConfigurationError, match=message):
        plugin.on_app_init(AppConfig(debug=False))


def test_oauth_plugin_routes_allow_localhost_redirects_in_debug_mode() -> None:
    """Debug mode keeps the explicit localhost OAuth plugin recipe available."""
    config = _minimal_litestar_auth_config()
    config.oauth_config = OAuthConfig(
        oauth_providers=[("example", object())],
        oauth_redirect_base_url="http://localhost/auth",
        oauth_token_encryption_key="YWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWE=",
    )
    plugin = LitestarAuth(config)

    result_config = plugin.on_app_init(AppConfig(debug=True))

    assert result_config is not None


def test_oauth_plugin_routes_allow_localhost_redirects_in_unsafe_testing_mode() -> None:
    """unsafe_testing keeps localhost plugin OAuth redirects available for app tests."""
    config = _minimal_litestar_auth_config()
    config.unsafe_testing = True
    config.oauth_config = OAuthConfig(
        oauth_providers=[("example", object())],
        oauth_redirect_base_url="http://localhost/auth",
        oauth_token_encryption_key="YWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWE=",
    )
    plugin = LitestarAuth(config)

    result_config = plugin.on_app_init(AppConfig(debug=False))

    assert result_config is not None


@pytest.mark.parametrize(
    ("oauth_config", "message"),
    [
        pytest.param(
            OAuthConfig(
                include_oauth_associate=True,
                oauth_token_encryption_key="YWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWE=",
            ),
            "include_oauth_associate=True requires oauth_providers",
            id="associate-flag-without-providers",
        ),
        pytest.param(
            OAuthConfig(
                oauth_providers=[("github", object())],
                oauth_token_encryption_key="YWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWE=",
            ),
            "oauth_redirect_base_url is required when oauth_providers are configured",
            id="providers-without-redirect-base",
        ),
        pytest.param(
            OAuthConfig(
                oauth_redirect_base_url="https://app.example.com/auth",
                oauth_token_encryption_key="YWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWE=",
            ),
            "oauth_redirect_base_url requires oauth_providers to be configured",
            id="redirect-base-without-providers",
        ),
    ],
)
def test_plugin_rejects_ambiguous_oauth_route_registration_contracts(
    oauth_config: OAuthConfig,
    message: str,
) -> None:
    """Ambiguous OAuth inventories fail at plugin construction before app init."""
    config = _minimal_litestar_auth_config()
    config.oauth_config = oauth_config

    with pytest.raises(ValueError, match=message):
        LitestarAuth(config)


@pytest.mark.parametrize(
    ("oauth_config", "expected_associate_path"),
    [
        pytest.param(
            OAuthConfig(
                oauth_providers=[("github", object())],
                oauth_redirect_base_url="https://app.example.com/auth",
                oauth_token_encryption_key="YWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWE=",
            ),
            None,
            id="login-only",
        ),
        pytest.param(
            OAuthConfig(
                oauth_providers=[("github", object())],
                include_oauth_associate=True,
                oauth_redirect_base_url="https://app.example.com/auth",
                oauth_token_encryption_key="YWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWE=",
            ),
            "/auth/associate/github",
            id="login-and-associate",
        ),
    ],
)
def test_plugin_mounts_oauth_routes_from_the_single_provider_inventory(
    oauth_config: OAuthConfig,
    expected_associate_path: str | None,
) -> None:
    """Plugin OAuth config auto-mounts login routes and optionally associate routes."""
    config = _minimal_litestar_auth_config()
    config.oauth_config = oauth_config
    result_config = LitestarAuth(config).on_app_init(AppConfig())
    mounted_paths = {getattr(route_handler, "path", None) for route_handler in result_config.route_handlers}

    assert "/auth/oauth/github" in mounted_paths
    if expected_associate_path is None:
        assert "/auth/associate/github" not in mounted_paths
    else:
        assert expected_associate_path in mounted_paths


def test_plugin_openapi_security_uses_alternative_requirements_for_multiple_backends() -> None:
    """Protected plugin routes allow any configured backend in OpenAPI."""
    config = _minimal_litestar_auth_config(
        backends=[
            AuthenticationBackend[ExampleUser, UUID](
                name="bearer",
                transport=BearerTransport(),
                strategy=cast("Any", InMemoryTokenStrategy(token_prefix="bearer-openapi")),
            ),
            AuthenticationBackend[ExampleUser, UUID](
                name="cookie",
                transport=CookieTransport(
                    cookie_name="auth_cookie",
                    allow_insecure_cookie_auth=True,
                    secure=False,
                ),
                strategy=cast("Any", InMemoryTokenStrategy(token_prefix="cookie-openapi")),
            ),
        ],
    )
    app = Litestar(
        plugins=[LitestarAuth(config)],
        openapi_config=OpenAPIConfig(title="Test", version="1.0.0"),
    )

    paths = cast("Any", app.openapi_schema.paths)
    logout_operation = paths["/auth/logout"].post

    assert logout_operation.security == [{"bearer": []}, {"cookie": []}]


def test_plugin_oauth_associate_callback_is_marked_protected_in_openapi() -> None:
    """Plugin-owned OAuth associate authorize and callback operations share the same security metadata."""
    config = _minimal_litestar_auth_config()
    config.oauth_config = OAuthConfig(
        oauth_providers=[("github", _OpenAPIOAuthClient())],
        include_oauth_associate=True,
        oauth_redirect_base_url="https://app.example.com/auth",
        oauth_token_encryption_key="YWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWE=",
    )
    app = Litestar(
        plugins=[LitestarAuth(config)],
        openapi_config=OpenAPIConfig(title="Test", version="1.0.0"),
    )
    paths = cast("Any", app.openapi_schema.paths)

    assert paths["/auth/associate/github/authorize"].get.security == [{"primary": []}]
    assert paths["/auth/associate/github/callback"].get.security == [{"primary": []}]


def test_app_owned_routes_can_reuse_plugin_openapi_security_requirements() -> None:
    """Application-defined protected routes can share the plugin's OpenAPI auth metadata."""
    config = _minimal_litestar_auth_config()
    protected_security = config.resolve_openapi_security_requirements()

    @get("/app-protected", guards=[is_authenticated], security=protected_security, sync_to_thread=False)
    def app_protected() -> dict[str, bool]:
        return {"ok": True}

    app = Litestar(
        route_handlers=[app_protected],
        plugins=[LitestarAuth(config)],
        openapi_config=OpenAPIConfig(title="Test", version="1.0.0"),
    )
    paths = cast("Any", app.openapi_schema.paths)
    security_schemes = cast("Any", app.openapi_schema.components.security_schemes)

    assert paths["/app-protected"].get.security == [{"primary": []}]
    assert "primary" in security_schemes


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
        session_maker=cast(
            "async_sessionmaker[AsyncSession]",
            assert_structural_session_factory(DummySessionMaker()),
        ),
        user_model=ExampleUser,
        user_manager_class=PluginUserManager,
        user_db_factory=lambda _session: user_db,
        user_manager_security=UserManagerSecurity[UUID](
            verification_token_secret="verify-secret-12345678901234567890",
            reset_password_token_secret="reset-secret-123456789012345678901",
            id_parser=UUID,
            password_helper=password_helper,
        ),
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


async def test_manual_backends_dependency_preserves_order_and_binds_request_session() -> None:
    """The request DI surface returns manual backends in startup order with request-bound strategies."""

    class _SessionAwareStrategy(InMemoryTokenStrategy):
        def __init__(self, *, token_prefix: str) -> None:
            super().__init__(token_prefix=token_prefix)
            self.bound_session: object | None = None

        def with_session(self, session: object) -> _SessionAwareStrategy:
            self.bound_session = session
            return self

    @get("/manual-backends-probe", sync_to_thread=False)
    def manual_backends_probe(
        db_session: object,
        litestar_auth_backends: object,
    ) -> dict[str, object]:
        backends = cast("list[AuthenticationBackend[ExampleUser, UUID]]", litestar_auth_backends)
        return {
            "backend_names": [configured_backend.name for configured_backend in backends],
            "strategy_sessions_match_db_session": [
                getattr(configured_backend.strategy, "bound_session", None) is db_session
                for configured_backend in backends
            ],
        }

    primary_backend = AuthenticationBackend[ExampleUser, UUID](
        name="primary",
        transport=BearerTransport(),
        strategy=cast("Any", _SessionAwareStrategy(token_prefix="primary")),
    )
    secondary_backend = AuthenticationBackend[ExampleUser, UUID](
        name="secondary",
        transport=BearerTransport(),
        strategy=cast("Any", _SessionAwareStrategy(token_prefix="secondary")),
    )
    config = _minimal_litestar_auth_config(backends=[primary_backend, secondary_backend])
    app = Litestar(route_handlers=[manual_backends_probe], plugins=[LitestarAuth(config)])

    async with AsyncTestClient(app=app) as client:
        response = await client.get("/manual-backends-probe")

    assert response.status_code == HTTP_OK
    assert response.json() == {
        "backend_names": ["primary", "secondary"],
        "strategy_sessions_match_db_session": [True, True],
    }


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
        totp_pending_jti_store=InMemoryJWTDenylistStore(),
        totp_used_tokens_store=cast("Any", object()),
    )
    config.user_manager_security = UserManagerSecurity[UUID](
        verification_token_secret="verify-secret-12345678901234567890",
        reset_password_token_secret="reset-secret-123456789012345678901",
        totp_secret_key=Fernet.generate_key().decode(),
        id_parser=UUID,
    )
    plugin = LitestarAuth(config)

    startup_backend = plugin._totp_backend()

    assert isinstance(startup_backend, plugin_module.StartupBackendTemplate)
    assert startup_backend.name == secondary_backend.name
    assert startup_backend.transport is secondary_backend.transport
    assert startup_backend.strategy is secondary_backend.strategy


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
        totp_pending_jti_store=InMemoryJWTDenylistStore(),
        totp_used_tokens_store=cast("Any", object()),
    )
    config.user_manager_security = UserManagerSecurity[UUID](
        verification_token_secret="verify-secret-12345678901234567890",
        reset_password_token_secret="reset-secret-123456789012345678901",
        totp_secret_key=Fernet.generate_key().decode(),
        id_parser=UUID,
    )
    plugin = LitestarAuth(config)

    with pytest.raises(ValueError, match="unknown-backend"):
        plugin._totp_backend()


def test_refresh_enabled_bearer_backends_mount_refresh_routes_in_backend_order() -> None:
    """Refresh-enabled bearer backends keep primary/secondary route names and ordering stable."""
    primary_backend = AuthenticationBackend[ExampleUser, UUID](
        name="primary",
        transport=BearerTransport(),
        strategy=cast("Any", InMemoryRefreshTokenStrategy(token_prefix="primary")),
    )
    secondary_backend = AuthenticationBackend[ExampleUser, UUID](
        name="secondary",
        transport=BearerTransport(),
        strategy=cast("Any", InMemoryRefreshTokenStrategy(token_prefix="secondary")),
    )
    config = _minimal_litestar_auth_config(backends=[primary_backend, secondary_backend])
    config.enable_refresh = True
    config.include_register = False
    config.include_verify = False
    config.include_reset_password = False

    app = Litestar(plugins=[LitestarAuth(config)])
    auth_route_paths = [route.path_format for route in app.routes if route.path_format.startswith("/auth")]

    assert auth_route_paths == [
        "/auth/login",
        "/auth/logout",
        "/auth/refresh",
        "/auth/secondary/login",
        "/auth/secondary/logout",
        "/auth/secondary/refresh",
    ]


def test_database_token_preset_mounts_primary_auth_routes_without_startup_session() -> None:
    """The preset keeps primary auth paths stable without requiring a startup AsyncSession."""
    session_maker = assert_structural_session_factory(DummySessionMaker())
    config = LitestarAuthConfig[ExampleUser, UUID](
        database_token_auth=DatabaseTokenAuthConfig(
            token_hash_secret="x" * 40,
            backend_name="opaque-db",
        ),
        user_model=ExampleUser,
        user_manager_class=PluginUserManager,
        session_maker=cast("async_sessionmaker[AsyncSession]", session_maker),
        user_db_factory=lambda _session: InMemoryUserDatabase([]),
        user_manager_security=UserManagerSecurity[UUID](
            verification_token_secret="verify-secret-12345678901234567890",
            reset_password_token_secret="reset-secret-123456789012345678901",
            id_parser=UUID,
        ),
        enable_refresh=True,
        include_register=False,
        include_verify=False,
        include_reset_password=False,
    )

    app = Litestar(plugins=[LitestarAuth(config)])
    auth_route_paths = [route.path_format for route in app.routes if route.path_format.startswith("/auth")]

    assert auth_route_paths == [
        "/auth/login",
        "/auth/logout",
        "/auth/refresh",
    ]


async def test_database_token_preset_backends_dependency_uses_request_session() -> None:
    """The preset backends DI path accepts a SessionMaker-style adapter and binds the request session."""

    @get("/preset-backends-probe", sync_to_thread=False)
    def preset_backends_probe(
        db_session: object,
        litestar_auth_backends: object,
    ) -> dict[str, object]:
        backends = cast("list[AuthenticationBackend[ExampleUser, UUID]]", litestar_auth_backends)
        backend = backends[0]
        return {
            "backend_names": [configured_backend.name for configured_backend in backends],
            "strategy_session_is_db_session": getattr(backend.strategy, "session", None) is db_session,
        }

    engine = create_engine(
        "sqlite+pysqlite:///:memory:",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )
    try:
        session_maker = assert_structural_session_factory(E2ESessionMaker(engine))
        config = LitestarAuthConfig[ExampleUser, UUID](
            database_token_auth=DatabaseTokenAuthConfig(
                token_hash_secret="x" * 40,
                backend_name="opaque-db",
            ),
            user_model=ExampleUser,
            user_manager_class=PluginUserManager,
            session_maker=session_maker,
            user_db_factory=lambda _session: InMemoryUserDatabase([]),
            user_manager_security=UserManagerSecurity[UUID](
                verification_token_secret="verify-secret-12345678901234567890",
                reset_password_token_secret="reset-secret-123456789012345678901",
                id_parser=UUID,
            ),
            enable_refresh=True,
            include_register=False,
            include_verify=False,
            include_reset_password=False,
        )
        app = Litestar(route_handlers=[preset_backends_probe], plugins=[LitestarAuth(config)])

        async with AsyncTestClient(app=app) as client:
            response = await client.get("/preset-backends-probe")
    finally:
        engine.dispose()

    assert response.status_code == HTTP_OK
    assert response.json() == {
        "backend_names": ["opaque-db"],
        "strategy_session_is_db_session": True,
    }


async def test_database_token_preset_accepts_advanced_alchemy_session_maker() -> None:
    """The preset accepts ``SQLAlchemyAsyncConfig.session_maker`` without an adapter cast."""

    @get("/preset-aa-session-maker-probe", sync_to_thread=False)
    def preset_backends_probe(
        db_session: object,
        litestar_auth_backends: object,
    ) -> dict[str, object]:
        backends = cast("list[AuthenticationBackend[ExampleUser, UUID]]", litestar_auth_backends)
        backend = backends[0]
        return {
            "backend_names": [configured_backend.name for configured_backend in backends],
            "strategy_session_is_db_session": getattr(backend.strategy, "session", None) is db_session,
        }

    engine = create_engine(
        "sqlite+pysqlite:///:memory:",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )
    try:
        alchemy = SQLAlchemyAsyncConfig(session_maker=E2ESessionMaker(engine))
        session_maker = alchemy.session_maker
        assert session_maker is not None

        config = LitestarAuthConfig[ExampleUser, UUID](
            database_token_auth=DatabaseTokenAuthConfig(
                token_hash_secret="x" * 40,
                backend_name="opaque-db",
            ),
            user_model=ExampleUser,
            user_manager_class=PluginUserManager,
            session_maker=session_maker,
            user_db_factory=lambda _session: InMemoryUserDatabase([]),
            user_manager_security=UserManagerSecurity[UUID](
                verification_token_secret="verify-secret-12345678901234567890",
                reset_password_token_secret="reset-secret-123456789012345678901",
                id_parser=UUID,
            ),
            enable_refresh=True,
            include_register=False,
            include_verify=False,
            include_reset_password=False,
        )
        assert config.session_maker is session_maker

        app = Litestar(route_handlers=[preset_backends_probe], plugins=[LitestarAuth(config)])

        async with AsyncTestClient(app=app) as client:
            response = await client.get("/preset-aa-session-maker-probe")
    finally:
        engine.dispose()

    assert response.status_code == HTTP_OK
    assert response.json() == {
        "backend_names": ["opaque-db"],
        "strategy_session_is_db_session": True,
    }
