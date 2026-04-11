"""Unit tests for plugin config dataclasses and builder helpers."""

from __future__ import annotations

import importlib
from collections.abc import Callable, Sequence
from datetime import timedelta
from functools import partial
from typing import TYPE_CHECKING, Any, Literal, assert_type, cast, get_args, get_origin, get_type_hints
from uuid import UUID, uuid4

import msgspec
import pytest

import litestar_auth._plugin.config as plugin_config_module
from litestar_auth._plugin.config import (
    DatabaseTokenAuthConfig,
    OAuthConfig,
    TotpConfig,
    _build_oauth_route_registration_contract,
    build_user_manager,
    default_password_validator_factory,
    require_session_maker,
    resolve_password_validator,
    resolve_user_manager_factory,
)
from litestar_auth._plugin.scoped_session import SessionFactory
from litestar_auth.authentication.backend import AuthenticationBackend
from litestar_auth.authentication.strategy.db_models import AccessToken, RefreshToken
from litestar_auth.authentication.transport.bearer import BearerTransport
from litestar_auth.config import DEFAULT_MINIMUM_PASSWORD_LENGTH
from litestar_auth.exceptions import InvalidPasswordError
from litestar_auth.manager import BaseUserManager, UserManagerSecurity, require_password_length
from litestar_auth.password import PasswordHelper
from litestar_auth.plugin import LitestarAuthConfig
from litestar_auth.ratelimit import AuthRateLimitConfig
from litestar_auth.schemas import UserCreate
from tests.e2e.conftest import assert_structural_session_factory
from tests.integration.test_orchestrator import (
    DummySession,
    DummySessionMaker,
    ExampleUser,
    InMemoryTokenStrategy,
    InMemoryUserDatabase,
    PluginUserManager,
)

if TYPE_CHECKING:
    from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

pytestmark = pytest.mark.unit


def _current_startup_backend_template_type() -> type[Any]:
    """Resolve the current StartupBackendTemplate class to survive cross-test module reloads.

    Returns:
        The current StartupBackendTemplate type.
    """
    return cast("type[Any]", importlib.import_module("litestar_auth._plugin.config").StartupBackendTemplate)


def test_plugin_config_module_executes_under_coverage() -> None:
    """Reload the module in-test so coverage records module and dataclass execution."""
    reloaded_module = importlib.reload(plugin_config_module)

    assert reloaded_module.LitestarAuthConfig.__name__ == LitestarAuthConfig.__name__
    assert reloaded_module.DatabaseTokenAuthConfig.__name__ == DatabaseTokenAuthConfig.__name__
    assert reloaded_module.OAuthConfig.__name__ == OAuthConfig.__name__


def _minimal_config(  # noqa: PLR0913
    *,
    backends: list[AuthenticationBackend[ExampleUser, UUID]] | None = None,
    include_users: bool = False,
    totp_config: TotpConfig | None = None,
    user_manager_security: UserManagerSecurity[UUID] | None = None,
    user_manager_class: type[Any] | None = None,
    id_parser: type[UUID] | None = None,
    login_identifier: Literal["email", "username"] = "email",
) -> LitestarAuthConfig[ExampleUser, UUID]:
    """Build a minimal config for plugin tests.

    Returns:
        LitestarAuthConfig instance for the given options.
    """
    resolved_manager_security = user_manager_security or UserManagerSecurity[UUID](
        verification_token_secret="x" * 32,
        reset_password_token_secret="y" * 32,
    )
    user_db = InMemoryUserDatabase([])
    default_backend = AuthenticationBackend[ExampleUser, UUID](
        name="primary",
        transport=BearerTransport(),
        strategy=cast("Any", InMemoryTokenStrategy(token_prefix="plugin-config")),
    )
    strategies = backends if backends is not None else [default_backend]
    return LitestarAuthConfig[ExampleUser, UUID](
        backends=strategies,
        user_model=ExampleUser,
        user_manager_class=user_manager_class or PluginUserManager,
        session_maker=cast(
            "async_sessionmaker[AsyncSession]",
            assert_structural_session_factory(DummySessionMaker()),
        ),
        user_db_factory=lambda _session: user_db,
        user_manager_security=resolved_manager_security,
        user_manager_kwargs={},
        include_users=include_users,
        id_parser=id_parser,
        totp_config=totp_config,
        login_identifier=login_identifier,
    )


def test_litestar_auth_config_declares_oauth_config_field() -> None:
    """The plugin config exposes an explicit nested OAuth config field."""
    dataclass_fields = LitestarAuthConfig.__dataclass_fields__

    assert "oauth_config" in dataclass_fields


def test_litestar_auth_config_declares_password_validator_factory_fields() -> None:
    """The plugin config exposes explicit password-validator and manager-builder seams."""
    dataclass_fields = LitestarAuthConfig.__dataclass_fields__

    assert "password_validator_factory" in dataclass_fields
    assert "user_manager_factory" in dataclass_fields


def test_litestar_auth_config_declares_user_manager_security_field() -> None:
    """The plugin config exposes the typed manager-security contract explicitly."""
    dataclass_fields = LitestarAuthConfig.__dataclass_fields__

    assert "user_manager_security" in dataclass_fields


def test_litestar_auth_config_declares_db_session_dependency_fields() -> None:
    """The plugin config exposes db_session DI key and external-session declaration."""
    dataclass_fields = LitestarAuthConfig.__dataclass_fields__

    assert "db_session_dependency_key" in dataclass_fields
    assert "db_session_dependency_provided_externally" in dataclass_fields


def test_litestar_auth_config_declares_login_identifier_field() -> None:
    """The plugin config exposes login_identifier with a safe default."""
    dataclass_fields = LitestarAuthConfig.__dataclass_fields__

    assert "login_identifier" in dataclass_fields
    assert dataclass_fields["login_identifier"].default == "email"


def test_litestar_auth_config_login_identifier_defaults_to_email() -> None:
    """Default login mode is email."""
    config = _minimal_config()

    assert config.login_identifier == "email"


def test_litestar_auth_config_build_password_helper_memoizes_default_helper() -> None:
    """Config exposes one memoized helper for plugin and app-owned password work."""
    config = _minimal_config()

    first = config.build_password_helper()
    second = config.build_password_helper()

    assert first is second
    assert "password_helper" not in config.user_manager_kwargs
    assert first.password_hash.hashers[0].__class__.__name__ == "Argon2Hasher"
    assert first.password_hash.hashers[1].__class__.__name__ == "BcryptHasher"


def test_litestar_auth_config_build_password_helper_preserves_explicit_helper_override() -> None:
    """Config-level helper resolution keeps deliberate custom helper injection unchanged."""
    explicit_password_helper = PasswordHelper()
    config = _minimal_config()
    config.user_manager_kwargs["password_helper"] = explicit_password_helper

    assert config.build_password_helper() is explicit_password_helper


def test_litestar_auth_config_accepts_login_identifier_username() -> None:
    """Username mode is a valid explicit choice."""
    config = _minimal_config(login_identifier="username")

    assert config.login_identifier == "username"


def test_totp_config_defaults_match_expected_values() -> None:
    """TotpConfig exposes stable defaults for optional settings."""
    config = TotpConfig(totp_pending_secret="x" * 32)

    assert config.totp_backend_name is None
    assert config.totp_issuer == "litestar-auth"
    assert config.totp_algorithm == "SHA256"
    assert config.totp_used_tokens_store is None
    assert config.totp_pending_jti_store is None
    assert config.totp_require_replay_protection is True
    assert config.totp_enable_requires_password is True


def test_oauth_config_defaults_match_expected_values() -> None:
    """OAuthConfig exposes stable defaults for optional settings."""
    config = OAuthConfig()

    assert config.oauth_cookie_secure is True
    assert config.oauth_providers is None
    assert config.oauth_provider_scopes == {}
    assert config.oauth_associate_by_email is False
    assert config.oauth_trust_provider_email_verified is False
    assert config.include_oauth_associate is False
    assert not config.oauth_redirect_base_url
    assert config.oauth_token_encryption_key is None


def test_oauth_route_registration_contract_omits_redirects_without_plugin_owned_routes() -> None:
    """Without providers, the plugin-owned OAuth callback bases stay absent."""
    contract = _build_oauth_route_registration_contract(
        auth_path="/auth",
        oauth_config=OAuthConfig(),
    )

    assert contract.has_plugin_owned_login_routes is False
    assert contract.has_plugin_owned_associate_routes is False
    assert contract.login_redirect_base_url is None
    assert contract.associate_redirect_base_url is None


def test_oauth_route_registration_contract_derives_login_and_associate_redirect_bases() -> None:
    """A shared OAuth redirect base fans out to login and associate callback prefixes."""
    contract = _build_oauth_route_registration_contract(
        auth_path="/auth/",
        oauth_config=OAuthConfig(
            oauth_providers=[("github", object())],
            include_oauth_associate=True,
            oauth_redirect_base_url="https://app.example/auth/",
        ),
    )

    assert contract.has_plugin_owned_login_routes is True
    assert contract.has_plugin_owned_associate_routes is True
    assert contract.login_path == "/auth/oauth"
    assert contract.associate_path == "/auth/associate"
    assert contract.login_redirect_base_url == "https://app.example/auth/oauth"
    assert contract.associate_redirect_base_url == "https://app.example/auth/associate"


def test_oauth_route_registration_contract_normalizes_per_provider_scopes() -> None:
    """Configured plugin-owned OAuth scopes are normalized per provider."""
    contract = _build_oauth_route_registration_contract(
        auth_path="/auth/",
        oauth_config=OAuthConfig(
            oauth_providers=[("github", object()), ("gitlab", object())],
            oauth_provider_scopes={"github": ["openid", "email", "openid"]},
            oauth_redirect_base_url="https://app.example/auth/",
        ),
    )

    assert contract.oauth_provider_scopes == {"github": ("openid", "email")}


def test_oauth_route_registration_contract_omits_empty_provider_scope_lists() -> None:
    """Empty configured scope lists do not create a provider-scope entry."""
    contract = _build_oauth_route_registration_contract(
        auth_path="/auth/",
        oauth_config=OAuthConfig(
            oauth_providers=[("github", object())],
            oauth_provider_scopes={"github": []},
            oauth_redirect_base_url="https://app.example/auth/",
        ),
    )

    assert contract.oauth_provider_scopes == {}


def test_oauth_route_registration_contract_rejects_unknown_scope_provider_names() -> None:
    """Per-provider OAuth scopes must reference declared plugin-owned providers."""
    with pytest.raises(ValueError, match="oauth_provider_scopes contains unknown provider names: gitlab"):
        _build_oauth_route_registration_contract(
            auth_path="/auth/",
            oauth_config=OAuthConfig(
                oauth_providers=[("github", object())],
                oauth_provider_scopes={"gitlab": ["openid"]},
                oauth_redirect_base_url="https://app.example/auth/",
            ),
        )


@pytest.mark.parametrize(
    ("provider_scopes", "expected_error", "expected_message"),
    [
        ({"github": [cast("Any", object())]}, TypeError, "oauth_provider_scopes values must be strings"),
        ({"github": [""]}, ValueError, "oauth_provider_scopes values must be non-empty strings"),
        (
            {"github": ["openid email"]},
            ValueError,
            "oauth_provider_scopes values must be individual tokens without embedded whitespace",
        ),
    ],
)
def test_oauth_route_registration_contract_rejects_invalid_scope_values(
    provider_scopes: dict[str, list[object]],
    expected_error: type[Exception],
    expected_message: str,
) -> None:
    """Per-provider OAuth scopes reject invalid configured values."""
    with pytest.raises(expected_error, match=expected_message):
        _build_oauth_route_registration_contract(
            auth_path="/auth/",
            oauth_config=OAuthConfig(
                oauth_providers=[("github", object())],
                oauth_provider_scopes=cast("Any", provider_scopes),
                oauth_redirect_base_url="https://app.example/auth/",
            ),
        )


def test_litestar_auth_config_database_token_auth_defaults_to_none() -> None:
    """Manual backend configs expose no DB bearer preset metadata by default."""
    config = _minimal_config()

    assert config.database_token_auth is None


def test_database_token_auth_field_builds_canonical_db_bearer_backend() -> None:
    """The DB-token config field builds the canonical bearer + database-token backend lazily."""
    configured_token_bytes = 48
    session_maker = assert_structural_session_factory(DummySessionMaker())
    config = LitestarAuthConfig[ExampleUser, UUID](
        database_token_auth=DatabaseTokenAuthConfig(
            token_hash_secret="x" * 40,
            max_age=timedelta(minutes=5),
            refresh_max_age=timedelta(hours=12),
            token_bytes=configured_token_bytes,
            accept_legacy_plaintext_tokens=True,
        ),
        user_model=ExampleUser,
        user_manager_class=PluginUserManager,
        session_maker=cast("async_sessionmaker[AsyncSession]", session_maker),
        user_db_factory=lambda _session: InMemoryUserDatabase([]),
        user_manager_security=UserManagerSecurity[UUID](
            verification_token_secret="x" * 32,
            reset_password_token_secret="y" * 32,
        ),
    )

    preset = config.database_token_auth
    assert preset is not None
    assert not hasattr(preset, "session")
    assert preset.token_hash_secret == "x" * 40
    assert preset.max_age == timedelta(minutes=5)
    assert preset.refresh_max_age == timedelta(hours=12)
    assert preset.token_bytes == configured_token_bytes
    assert preset.accept_legacy_plaintext_tokens is True

    backend = config.startup_backends()[0]
    assert isinstance(backend, _current_startup_backend_template_type())
    assert backend.name == "database"
    assert isinstance(backend.transport, BearerTransport)
    current_strategy_module = importlib.import_module("litestar_auth.authentication.strategy")
    assert isinstance(backend.strategy, current_strategy_module.DatabaseTokenStrategy)
    assert backend.strategy.max_age == timedelta(minutes=5)
    assert backend.strategy.refresh_max_age == timedelta(hours=12)
    assert backend.strategy.token_bytes == configured_token_bytes
    assert backend.strategy.accept_legacy_plaintext_tokens is True
    assert require_session_maker(config) is session_maker


def test_startup_backends_wrap_manual_backends_in_startup_templates() -> None:
    """Manual backends are exposed through the startup-only template type."""
    backend = AuthenticationBackend[ExampleUser, UUID](
        name="manual",
        transport=BearerTransport(),
        strategy=cast("Any", InMemoryTokenStrategy(token_prefix="manual")),
    )
    config = _minimal_config(backends=[backend])

    startup_backend = config.startup_backends()[0]

    assert isinstance(startup_backend, _current_startup_backend_template_type())
    assert startup_backend.name == backend.name
    assert startup_backend.transport is backend.transport
    assert startup_backend.strategy is backend.strategy


def test_startup_database_token_templates_do_not_embed_a_placeholder_session() -> None:
    """Startup-only DB-token templates carry strategy metadata without a fake session object."""
    config = LitestarAuthConfig[ExampleUser, UUID](
        database_token_auth=DatabaseTokenAuthConfig(
            token_hash_secret="x" * 40,
        ),
        user_model=ExampleUser,
        user_manager_class=PluginUserManager,
        session_maker=cast(
            "async_sessionmaker[AsyncSession]",
            assert_structural_session_factory(DummySessionMaker()),
        ),
        user_db_factory=lambda _session: InMemoryUserDatabase([]),
        user_manager_security=UserManagerSecurity[UUID](
            verification_token_secret="x" * 32,
            reset_password_token_secret="y" * 32,
        ),
    )

    startup_backend = config.startup_backends()[0]

    assert "session" not in vars(cast("Any", startup_backend.strategy))


def test_resolve_database_token_strategy_session_without_session_fails_closed() -> None:
    """The legacy helper still returns a placeholder that raises the canonical runtime error."""
    startup_session = plugin_config_module.resolve_database_token_strategy_session()

    with pytest.raises(RuntimeError, match="startup_backends\\(\\) returns startup-only backends"):
        _ = cast("Any", startup_session).execute


def test_startup_backend_template_eq_identity_short_circuits() -> None:
    """StartupBackendTemplate.__eq__ returns True for the same instance."""
    backend = AuthenticationBackend[ExampleUser, UUID](
        name="a",
        transport=BearerTransport(),
        strategy=cast("Any", InMemoryTokenStrategy(token_prefix="a")),
    )
    template = plugin_config_module.StartupBackendTemplate.from_runtime_backend(backend)
    assert template == template  # noqa: PLR0124


def test_startup_backend_template_eq_rejects_foreign_type() -> None:
    """StartupBackendTemplate.__eq__ returns NotImplemented for non-template types."""
    backend = AuthenticationBackend[ExampleUser, UUID](
        name="a",
        transport=BearerTransport(),
        strategy=cast("Any", InMemoryTokenStrategy(token_prefix="a")),
    )
    template = plugin_config_module.StartupBackendTemplate.from_runtime_backend(backend)
    assert template != "not-a-template"


def test_startup_backend_template_hash_consistent_with_eq() -> None:
    """Equal StartupBackendTemplate instances produce the same hash."""
    backend = AuthenticationBackend[ExampleUser, UUID](
        name="a",
        transport=BearerTransport(),
        strategy=cast("Any", InMemoryTokenStrategy(token_prefix="a")),
    )
    t1 = plugin_config_module.StartupBackendTemplate.from_runtime_backend(backend)
    t2 = plugin_config_module.StartupBackendTemplate.from_runtime_backend(backend)
    assert t1 == t2
    assert hash(t1) == hash(t2)


async def test_startup_database_token_templates_fail_closed_for_runtime_db_work() -> None:
    """Startup-only DB-token templates fail closed if callers skip request-session binding."""
    config = LitestarAuthConfig[ExampleUser, UUID](
        database_token_auth=DatabaseTokenAuthConfig(
            token_hash_secret="x" * 40,
        ),
        user_model=ExampleUser,
        user_manager_class=PluginUserManager,
        session_maker=cast(
            "async_sessionmaker[AsyncSession]",
            assert_structural_session_factory(DummySessionMaker()),
        ),
        user_db_factory=lambda _session: InMemoryUserDatabase([]),
        user_manager_security=UserManagerSecurity[UUID](
            verification_token_secret="x" * 32,
            reset_password_token_secret="y" * 32,
        ),
    )
    startup_backend = config.startup_backends()[0]
    user = ExampleUser(id=uuid4())

    with pytest.raises(RuntimeError, match="startup_backends\\(\\) returns startup-only backends"):
        await cast("Any", startup_backend.strategy).write_token(user)


async def test_startup_database_token_templates_fail_closed_for_remaining_runtime_db_methods() -> None:
    """Startup-only DB-token templates reject the full runtime DB-token method surface."""
    config = LitestarAuthConfig[ExampleUser, UUID](
        database_token_auth=DatabaseTokenAuthConfig(
            token_hash_secret="x" * 40,
        ),
        user_model=ExampleUser,
        user_manager_class=PluginUserManager,
        session_maker=cast(
            "async_sessionmaker[AsyncSession]",
            assert_structural_session_factory(DummySessionMaker()),
        ),
        user_db_factory=lambda _session: InMemoryUserDatabase([]),
        user_manager_security=UserManagerSecurity[UUID](
            verification_token_secret="x" * 32,
            reset_password_token_secret="y" * 32,
        ),
        enable_refresh=True,
    )
    startup_strategy = cast("Any", config.startup_backends()[0].strategy)
    user = ExampleUser(id=uuid4())
    runtime_calls = (
        startup_strategy.read_token(None, object()),
        startup_strategy.destroy_token("token", user),
        startup_strategy.write_refresh_token(user),
        startup_strategy.rotate_refresh_token("refresh", object()),
        startup_strategy.invalidate_all_tokens(user),
        startup_strategy.cleanup_expired_tokens(cast("Any", DummySession())),
    )

    for operation in runtime_calls:
        with pytest.raises(RuntimeError, match="startup_backends\\(\\) returns startup-only backends"):
            await operation


def test_build_database_token_backend_binds_the_explicit_runtime_session() -> None:
    """The direct runtime builder still returns a real session-bound DB-token backend."""
    active_session = DummySession()
    backend = plugin_config_module.build_database_token_backend(
        DatabaseTokenAuthConfig(
            token_hash_secret="x" * 40,
            backend_name="opaque-db",
            refresh_max_age=timedelta(days=14),
            accept_legacy_plaintext_tokens=True,
        ),
        session=cast("Any", active_session),
        unsafe_testing=True,
    )
    current_strategy_module = importlib.import_module("litestar_auth.authentication.strategy")

    assert backend.name == "opaque-db"
    assert isinstance(backend.strategy, current_strategy_module.DatabaseTokenStrategy)
    assert cast("Any", backend.strategy).session is active_session
    assert cast("Any", backend.strategy).refresh_max_age == timedelta(days=14)
    assert cast("Any", backend.strategy).accept_legacy_plaintext_tokens is True


def test_database_token_auth_rejects_manual_backends() -> None:
    """Explicit backends and the canonical DB-token preset are mutually exclusive."""
    backend = AuthenticationBackend[ExampleUser, UUID](
        name="primary",
        transport=BearerTransport(),
        strategy=cast("Any", InMemoryTokenStrategy(token_prefix="plugin-config")),
    )

    with pytest.raises(ValueError, match=r"database_token_auth=\.\.\. or backends=\.\.\., not both"):
        LitestarAuthConfig[ExampleUser, UUID](
            database_token_auth=DatabaseTokenAuthConfig(
                token_hash_secret="x" * 40,
            ),
            backends=[backend],
            user_model=ExampleUser,
            user_manager_class=PluginUserManager,
            session_maker=cast(
                "async_sessionmaker[AsyncSession]",
                assert_structural_session_factory(DummySessionMaker()),
            ),
            user_db_factory=lambda _session: InMemoryUserDatabase([]),
            user_manager_security=UserManagerSecurity[UUID](
                verification_token_secret="x" * 32,
                reset_password_token_secret="y" * 32,
            ),
        )


def test_resolve_backends_rejects_database_token_preset_and_directs_callers_to_explicit_contract() -> None:
    """`resolve_backends()` only supports the explicit manual-backend surface."""
    config = LitestarAuthConfig[ExampleUser, UUID](
        database_token_auth=DatabaseTokenAuthConfig(
            token_hash_secret="x" * 40,
        ),
        user_model=ExampleUser,
        user_manager_class=PluginUserManager,
        session_maker=cast(
            "async_sessionmaker[AsyncSession]",
            assert_structural_session_factory(DummySessionMaker()),
        ),
        user_db_factory=lambda _session: InMemoryUserDatabase([]),
        user_manager_security=UserManagerSecurity[UUID](
            verification_token_secret="x" * 32,
            reset_password_token_secret="y" * 32,
        ),
    )

    with pytest.raises(ValueError, match=r"Use startup_backends\(\) during plugin setup"):
        config.resolve_backends()


def test_resolve_backends_returns_manual_backends_without_database_token_preset() -> None:
    """`resolve_backends()` still returns the explicit manual backend sequence unchanged."""
    backend = AuthenticationBackend[ExampleUser, UUID](
        name="manual",
        transport=BearerTransport(),
        strategy=cast("Any", InMemoryTokenStrategy(token_prefix="manual")),
    )
    config = _minimal_config(backends=[backend])

    assert config.resolve_backends() == [backend]


def test_bind_request_backends_preserves_manual_backend_inventory_order() -> None:
    """Manual backends stay on the explicit runtime surface and bind sessions in the same order."""

    class _SessionAwareStrategy(InMemoryTokenStrategy):
        def __init__(self, *, token_prefix: str) -> None:
            super().__init__(token_prefix=token_prefix)
            self.sessions_seen: list[object] = []

        def with_session(self, session: object) -> _SessionAwareStrategy:
            self.sessions_seen.append(session)
            return self

    primary_strategy = _SessionAwareStrategy(token_prefix="primary")
    secondary_strategy = _SessionAwareStrategy(token_prefix="secondary")
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
    config = _minimal_config(backends=[primary_backend, secondary_backend])
    active_session = DummySession()

    runtime_backends = config.bind_request_backends(cast("Any", active_session))

    assert runtime_backends == (primary_backend, secondary_backend)
    assert primary_strategy.sessions_seen == [active_session]
    assert secondary_strategy.sessions_seen == [active_session]


def test_bind_request_backends_realizes_database_token_preset_from_request_session() -> None:
    """The DB-token preset exposes startup templates and request-scoped runtime backends separately."""
    config = LitestarAuthConfig[ExampleUser, UUID](
        database_token_auth=DatabaseTokenAuthConfig(
            token_hash_secret="x" * 40,
            backend_name="opaque-db",
            refresh_max_age=timedelta(days=14),
            accept_legacy_plaintext_tokens=True,
        ),
        user_model=ExampleUser,
        user_manager_class=PluginUserManager,
        session_maker=cast(
            "async_sessionmaker[AsyncSession]",
            assert_structural_session_factory(DummySessionMaker()),
        ),
        user_db_factory=lambda _session: InMemoryUserDatabase([]),
        user_manager_security=UserManagerSecurity[UUID](
            verification_token_secret="x" * 32,
            reset_password_token_secret="y" * 32,
        ),
        enable_refresh=True,
    )
    active_session = DummySession()

    startup_backend = config.startup_backends()[0]
    runtime_backends = config.bind_request_backends(cast("Any", active_session))
    current_strategy_module = importlib.import_module("litestar_auth.authentication.strategy")

    assert isinstance(startup_backend, _current_startup_backend_template_type())
    assert len(runtime_backends) == 1
    assert isinstance(runtime_backends[0], AuthenticationBackend)
    assert runtime_backends[0].name == "opaque-db"
    assert runtime_backends[0] is not startup_backend
    assert isinstance(startup_backend.strategy, current_strategy_module.DatabaseTokenStrategy)
    assert isinstance(runtime_backends[0].strategy, current_strategy_module.DatabaseTokenStrategy)
    assert cast("Any", runtime_backends[0].strategy).session is active_session
    assert cast("Any", runtime_backends[0].strategy).refresh_max_age == timedelta(days=14)
    assert cast("Any", runtime_backends[0].strategy).accept_legacy_plaintext_tokens is True


def test_startup_backends_reject_post_init_mixing_of_preset_and_manual_backends() -> None:
    """`startup_backends()` fails closed if callers mutate the config into an invalid mixed state."""
    config = LitestarAuthConfig[ExampleUser, UUID](
        database_token_auth=DatabaseTokenAuthConfig(
            token_hash_secret="x" * 40,
        ),
        user_model=ExampleUser,
        user_manager_class=PluginUserManager,
        session_maker=cast(
            "async_sessionmaker[AsyncSession]",
            assert_structural_session_factory(DummySessionMaker()),
        ),
        user_db_factory=lambda _session: InMemoryUserDatabase([]),
        user_manager_security=UserManagerSecurity[UUID](
            verification_token_secret="x" * 32,
            reset_password_token_secret="y" * 32,
        ),
    )
    config.backends = [
        AuthenticationBackend[ExampleUser, UUID](
            name="primary",
            transport=BearerTransport(),
            strategy=cast("Any", InMemoryTokenStrategy(token_prefix="plugin-config")),
        ),
    ]

    with pytest.raises(ValueError, match=r"database_token_auth=\.\.\. or backends=\.\.\., not both"):
        config.startup_backends()


def test_resolve_password_validator_uses_fixed_default_builder_contract() -> None:
    """Password-validator resolution no longer probes manager constructor signatures."""

    class _ManagerWithoutPasswordValidator:
        def __init__(self, user_db: object) -> None:
            del user_db

    config = _minimal_config(user_manager_class=cast("type[Any]", _ManagerWithoutPasswordValidator))

    validator = resolve_password_validator(config)

    assert validator is not None
    with pytest.raises(ValueError, match=rf"at least {DEFAULT_MINIMUM_PASSWORD_LENGTH}"):
        validator("short")


def test_resolve_password_validator_prefers_explicit_validator_over_factory() -> None:
    """Legacy kwargs injection takes precedence over factory/default validator resolution."""

    def explicit_validator(password: str) -> None:
        require_password_length(password, 20)

    config = _minimal_config()
    config.user_manager_kwargs["password_validator"] = explicit_validator
    config.password_validator_factory = lambda _config: lambda password: require_password_length(password, 10)

    assert resolve_password_validator(config) is explicit_validator


def test_resolve_password_validator_uses_factory_before_default() -> None:
    """Explicit factories outrank the built-in password-length validator."""

    def factory_validator(password: str) -> None:
        require_password_length(password, 10)

    config = _minimal_config()
    config.password_validator_factory = lambda _config: factory_validator

    assert resolve_password_validator(config) is factory_validator


def test_resolve_password_validator_returns_default_for_default_builder() -> None:
    """The fixed default builder injects the built-in password policy when unconfigured."""
    config = _minimal_config()

    validator = resolve_password_validator(config)

    assert validator is not None
    with pytest.raises(ValueError, match=rf"at least {DEFAULT_MINIMUM_PASSWORD_LENGTH}"):
        validator("short")


def test_default_password_validator_factory_enforces_repository_default_length() -> None:
    """The default factory uses the shared minimum-password constant."""
    validator = default_password_validator_factory(_minimal_config())

    with pytest.raises(ValueError, match=rf"at least {DEFAULT_MINIMUM_PASSWORD_LENGTH}"):
        validator("short")


def test_build_user_manager_respects_existing_password_validator_and_login_identifier_kwargs() -> None:
    """Explicit manager kwargs are preserved instead of being overwritten by helper defaults."""

    def explicit_password_validator(password: str) -> None:
        require_password_length(password, 10)

    user_db = InMemoryUserDatabase([])
    config = _minimal_config(login_identifier="username")
    config.user_manager_kwargs["password_validator"] = explicit_password_validator
    config.user_manager_kwargs["login_identifier"] = "email"

    manager = build_user_manager(
        session=cast("Any", DummySession()),
        user_db=user_db,
        config=config,
        backends=("bound-backend",),
    )

    assert manager.password_validator is explicit_password_validator
    assert manager.login_identifier == "email"
    assert manager.backends == ("bound-backend",)


def test_build_user_manager_injects_default_password_helper_without_prior_materialization() -> None:
    """The default builder always supplies the shared helper even before app-owned code asks for it."""

    class _PasswordHelperRequiredManager(PluginUserManager):
        def __init__(  # noqa: PLR0913
            self,
            user_db: object,
            *,
            password_helper: PasswordHelper,
            security: UserManagerSecurity[UUID] | None = None,
            password_validator: Callable[[str], None] | None = None,
            backends: tuple[object, ...] = (),
            login_identifier: Literal["email", "username"] = "email",
            unsafe_testing: bool = False,
        ) -> None:
            self.received_password_helper = password_helper
            super().__init__(
                cast("Any", user_db),
                password_helper=password_helper,
                security=security,
                password_validator=password_validator,
                backends=backends,
                login_identifier=login_identifier,
                unsafe_testing=unsafe_testing,
            )

    config = _minimal_config()
    config.user_manager_class = _PasswordHelperRequiredManager

    assert config.memoized_default_password_helper() is None

    manager = cast(
        "Any",
        build_user_manager(
            session=cast("Any", DummySession()),
            user_db=InMemoryUserDatabase([]),
            config=config,
        ),
    )

    hashed_password = manager.received_password_helper.hash("shared-password")

    assert manager.received_password_helper.verify("shared-password", hashed_password) is True
    assert manager.password_helper is manager.received_password_helper
    assert config.memoized_default_password_helper() is manager.received_password_helper


async def test_build_user_manager_preserves_explicit_none_password_validator_override() -> None:
    """A legacy ``password_validator=None`` entry still suppresses injected validators."""

    def generated_validator(password: str) -> None:
        require_password_length(password, DEFAULT_MINIMUM_PASSWORD_LENGTH + 4)

    config = _minimal_config()
    config.password_validator_factory = lambda _config: generated_validator
    config.user_manager_kwargs["password_validator"] = None

    manager = build_user_manager(
        session=cast("Any", DummySession()),
        user_db=InMemoryUserDatabase([]),
        config=config,
    )

    assert manager.password_validator is None

    created_user = await manager.create(
        UserCreate(
            email="legacy-none@example.com",
            password="p" * DEFAULT_MINIMUM_PASSWORD_LENGTH,
        ),
    )

    assert manager.password_helper.verify("p" * DEFAULT_MINIMUM_PASSWORD_LENGTH, created_user.hashed_password) is True


async def test_build_user_manager_applies_current_password_surface_from_config() -> None:
    """The default manager builder preserves the documented password-surface inputs."""
    verification_secret = "v" * 32
    reset_secret = "r" * 32
    minimum_length = DEFAULT_MINIMUM_PASSWORD_LENGTH + 4

    config = _minimal_config(login_identifier="username")
    config.user_manager_security = UserManagerSecurity[UUID](
        verification_token_secret=verification_secret,
        reset_password_token_secret=reset_secret,
    )
    password_helper = config.build_password_helper()

    def factory(config: LitestarAuthConfig[ExampleUser, UUID]) -> Callable[[str], None]:
        assert config.memoized_default_password_helper() is password_helper
        assert "password_helper" not in config.user_manager_kwargs
        assert config.user_manager_security is not None
        assert config.user_manager_security.verification_token_secret == verification_secret
        assert config.user_manager_security.reset_password_token_secret == reset_secret
        return partial(require_password_length, minimum_length=minimum_length)

    config.password_validator_factory = factory

    manager = build_user_manager(
        session=cast("Any", DummySession()),
        user_db=InMemoryUserDatabase([]),
        config=config,
        backends=("bound-backend",),
    )

    assert manager.password_helper is password_helper
    assert manager.verification_token_secret.get_secret_value() == verification_secret
    assert manager.reset_password_token_secret.get_secret_value() == reset_secret
    assert manager.login_identifier == "username"
    assert manager.backends == ("bound-backend",)

    with pytest.raises(InvalidPasswordError, match=rf"at least {minimum_length}"):
        await manager.create(
            UserCreate(
                email="consumer@example.com",
                password="p" * DEFAULT_MINIMUM_PASSWORD_LENGTH,
            ),
        )

    created_user = await manager.create(
        UserCreate(
            email="consumer@example.com",
            password="p" * minimum_length,
        ),
    )

    assert password_helper.verify("p" * minimum_length, created_user.hashed_password) is True


async def test_build_user_manager_prefers_typed_manager_security_contract() -> None:
    """The canonical typed security bundle feeds manager secret and parser wiring."""
    password_helper = PasswordHelper()
    verification_secret = "v" * 32
    reset_secret = "r" * 32
    totp_secret_key = "t" * 32
    minimum_length = DEFAULT_MINIMUM_PASSWORD_LENGTH + 4

    def factory(config: LitestarAuthConfig[ExampleUser, UUID]) -> Callable[[str], None]:
        assert config.user_manager_security is not None
        assert config.user_manager_security.verification_token_secret == verification_secret
        assert config.user_manager_security.reset_password_token_secret == reset_secret
        assert config.user_manager_security.totp_secret_key == totp_secret_key
        assert config.id_parser is UUID
        return partial(require_password_length, minimum_length=minimum_length)

    config = LitestarAuthConfig[ExampleUser, UUID](
        backends=_minimal_config().backends,
        user_model=ExampleUser,
        user_manager_class=PluginUserManager,
        session_maker=cast(
            "async_sessionmaker[AsyncSession]",
            assert_structural_session_factory(DummySessionMaker()),
        ),
        user_db_factory=lambda _session: InMemoryUserDatabase([]),
        user_manager_security=UserManagerSecurity[UUID](
            verification_token_secret=verification_secret,
            reset_password_token_secret=reset_secret,
            totp_secret_key=totp_secret_key,
            id_parser=UUID,
        ),
        user_manager_kwargs={"password_helper": password_helper},
        password_validator_factory=factory,
        login_identifier="username",
    )

    manager = build_user_manager(
        session=cast("Any", DummySession()),
        user_db=InMemoryUserDatabase([]),
        config=config,
        backends=("bound-backend",),
    )

    assert manager.password_helper is password_helper
    assert manager.verification_token_secret.get_secret_value() == verification_secret
    assert manager.reset_password_token_secret.get_secret_value() == reset_secret
    assert manager.totp_secret_key == totp_secret_key
    assert manager.id_parser is UUID
    assert manager.login_identifier == "username"
    assert manager.backends == ("bound-backend",)

    with pytest.raises(InvalidPasswordError, match=rf"at least {minimum_length}"):
        await manager.create(
            UserCreate(
                email="consumer@example.com",
                password="p" * DEFAULT_MINIMUM_PASSWORD_LENGTH,
            ),
        )

    created_user = await manager.create(
        UserCreate(
            email="consumer@example.com",
            password="p" * minimum_length,
        ),
    )

    assert password_helper.verify("p" * minimum_length, created_user.hashed_password) is True


def test_build_user_manager_passes_canonical_kwargs_through_kwargs_wrapper() -> None:
    """Kwargs wrappers still work when they preserve the canonical manager contract."""

    class _KwargsWrapperManager(PluginUserManager):
        def __init__(self, user_db: object, **kwargs: object) -> None:
            self.received_manager_kwargs = dict(kwargs)
            super().__init__(cast("Any", user_db), **cast("Any", self.received_manager_kwargs))

    verification_secret = "v" * 32
    reset_secret = "r" * 32
    totp_secret_key = "t" * 32
    config = LitestarAuthConfig[ExampleUser, UUID](
        backends=_minimal_config().backends,
        user_model=ExampleUser,
        user_manager_class=_KwargsWrapperManager,
        session_maker=cast(
            "async_sessionmaker[AsyncSession]",
            assert_structural_session_factory(DummySessionMaker()),
        ),
        user_db_factory=lambda _session: InMemoryUserDatabase([]),
        user_manager_security=UserManagerSecurity[UUID](
            verification_token_secret=verification_secret,
            reset_password_token_secret=reset_secret,
            totp_secret_key=totp_secret_key,
            id_parser=UUID,
        ),
        user_manager_kwargs={"password_helper": PasswordHelper()},
        login_identifier="username",
    )

    manager = build_user_manager(
        session=cast("Any", DummySession()),
        user_db=InMemoryUserDatabase([]),
        config=config,
        backends=("bound-backend",),
    )
    typed_manager = cast("Any", manager)

    assert typed_manager.received_manager_kwargs["security"].verification_token_secret == verification_secret
    assert typed_manager.received_manager_kwargs["security"].reset_password_token_secret == reset_secret
    assert typed_manager.received_manager_kwargs["security"].totp_secret_key == totp_secret_key
    assert typed_manager.received_manager_kwargs["security"].id_parser is UUID
    assert "verification_token_secret" not in typed_manager.received_manager_kwargs
    assert "reset_password_token_secret" not in typed_manager.received_manager_kwargs
    assert "totp_secret_key" not in typed_manager.received_manager_kwargs
    assert "id_parser" not in typed_manager.received_manager_kwargs
    assert manager.id_parser is UUID
    assert manager.login_identifier == "username"
    assert manager.backends == ("bound-backend",)


def test_build_user_manager_passes_typed_security_to_security_only_manager() -> None:
    """The fixed default builder forwards the typed security bundle end-to-end."""

    class _SecurityOnlyManager(PluginUserManager):
        def __init__(  # noqa: PLR0913
            self,
            user_db: object,
            *,
            password_helper: PasswordHelper | None = None,
            security: UserManagerSecurity[UUID],
            password_validator: object | None = None,
            backends: tuple[object, ...] = (),
            login_identifier: Literal["email", "username"] = "email",
            unsafe_testing: bool = False,
        ) -> None:
            self.received_security = security
            super().__init__(
                cast("Any", user_db),
                password_helper=password_helper,
                security=security,
                password_validator=cast("Any", password_validator),
                backends=backends,
                login_identifier=login_identifier,
                unsafe_testing=unsafe_testing,
            )

    verification_secret = "v" * 32
    reset_secret = "r" * 32
    totp_secret_key = "t" * 32
    config = LitestarAuthConfig[ExampleUser, UUID](
        backends=_minimal_config().backends,
        user_model=ExampleUser,
        user_manager_class=_SecurityOnlyManager,
        session_maker=cast(
            "async_sessionmaker[AsyncSession]",
            assert_structural_session_factory(DummySessionMaker()),
        ),
        user_db_factory=lambda _session: InMemoryUserDatabase([]),
        user_manager_security=UserManagerSecurity[UUID](
            verification_token_secret=verification_secret,
            reset_password_token_secret=reset_secret,
            totp_secret_key=totp_secret_key,
        ),
        user_manager_kwargs={"password_helper": PasswordHelper()},
        id_parser=UUID,
        login_identifier="username",
    )

    manager = build_user_manager(
        session=cast("Any", DummySession()),
        user_db=InMemoryUserDatabase([]),
        config=config,
        backends=("bound-backend",),
    )
    typed_manager = cast("Any", manager)

    assert typed_manager.received_security.verification_token_secret == verification_secret
    assert typed_manager.received_security.reset_password_token_secret == reset_secret
    assert typed_manager.received_security.totp_secret_key == totp_secret_key
    assert typed_manager.received_security.id_parser is UUID
    assert manager.id_parser is UUID
    assert manager.login_identifier == "username"
    assert manager.backends == ("bound-backend",)


def test_build_user_manager_requires_canonical_default_constructor_contract() -> None:
    """Managers that narrow the default constructor surface must use `user_manager_factory`."""

    class _LegacyManagerWithoutSecurity(PluginUserManager):
        def __init__(  # noqa: PLR0913
            self,
            user_db: object,
            *,
            password_helper: PasswordHelper | None = None,
            password_validator: object | None = None,
            verification_token_secret: str,
            reset_password_token_secret: str,
            backends: tuple[object, ...] = (),
        ) -> None:
            super().__init__(
                cast("Any", user_db),
                password_helper=password_helper,
                password_validator=cast("Any", password_validator),
                verification_token_secret=verification_token_secret,
                reset_password_token_secret=reset_password_token_secret,
                backends=backends,
            )

    verification_secret = "v" * 32
    reset_secret = "r" * 32
    totp_secret_key = "t" * 32
    config = LitestarAuthConfig[ExampleUser, UUID](
        backends=_minimal_config().backends,
        user_model=ExampleUser,
        user_manager_class=_LegacyManagerWithoutSecurity,
        session_maker=cast(
            "async_sessionmaker[AsyncSession]",
            assert_structural_session_factory(DummySessionMaker()),
        ),
        user_db_factory=lambda _session: InMemoryUserDatabase([]),
        user_manager_security=UserManagerSecurity[UUID](
            verification_token_secret=verification_secret,
            reset_password_token_secret=reset_secret,
            totp_secret_key=totp_secret_key,
        ),
        user_manager_kwargs={"password_helper": PasswordHelper()},
        id_parser=UUID,
        login_identifier="username",
    )

    with pytest.raises(TypeError, match="unexpected keyword argument 'security'"):
        _ = build_user_manager(
            session=cast("Any", DummySession()),
            user_db=InMemoryUserDatabase([]),
            config=config,
            backends=("bound-backend",),
        )


def test_build_user_manager_rejects_legacy_security_kwargs() -> None:
    """The default builder rejects plugin-managed secrets supplied through kwargs."""
    shared_secret = "shared-plugin-manager-secret-1234567890"
    config = _minimal_config()
    config.user_manager_security = None
    config.user_manager_kwargs.update(
        {
            "verification_token_secret": shared_secret,
            "reset_password_token_secret": shared_secret,
            "totp_secret_key": shared_secret,
        },
    )

    with pytest.raises(plugin_config_module.ConfigurationError, match=r"only accepts .* through user_manager_security"):
        _ = build_user_manager(
            session=cast("Any", DummySession()),
            user_db=InMemoryUserDatabase([]),
            config=config,
        )


def test_build_user_manager_preserves_explicit_unsafe_testing_kwarg() -> None:
    """Explicit manager kwargs remain the source of truth for unsafe-testing overrides."""

    class _UnsafeTestingManager(PluginUserManager):
        def __init__(  # noqa: PLR0913
            self,
            user_db: object,
            *,
            password_helper: PasswordHelper | None = None,
            security: UserManagerSecurity[UUID] | None = None,
            password_validator: Callable[[str], None] | None = None,
            backends: tuple[object, ...] = (),
            login_identifier: Literal["email", "username"] = "email",
            unsafe_testing: bool = False,
        ) -> None:
            self.received_unsafe_testing = unsafe_testing
            super().__init__(
                cast("Any", user_db),
                password_helper=password_helper,
                security=security,
                password_validator=password_validator,
                backends=backends,
                login_identifier=login_identifier,
                unsafe_testing=unsafe_testing,
            )

    config = _minimal_config()
    config.user_manager_class = _UnsafeTestingManager
    config.unsafe_testing = False
    config.user_manager_kwargs["unsafe_testing"] = True

    manager = cast(
        "Any",
        build_user_manager(
            session=cast("Any", DummySession()),
            user_db=InMemoryUserDatabase([]),
            config=config,
        ),
    )

    assert manager.received_unsafe_testing is True
    assert manager.unsafe_testing is True


def test_require_session_maker_returns_configured_session_maker() -> None:
    """require_session_maker returns a structurally compatible configured factory unchanged."""
    config = _minimal_config()

    assert require_session_maker(config) is config.session_maker


def test_require_session_maker_annotations_are_runtime_resolvable() -> None:
    """Runtime type-hint resolution for require_session_maker keeps the structural contract intact."""
    hints = get_type_hints(require_session_maker)

    assert hints["return"] is SessionFactory


def test_backend_split_annotations_are_runtime_resolvable() -> None:
    """Config methods keep startup/runtime backend types distinct in runtime-resolved hints."""
    current_startup_backend_template = plugin_config_module.StartupBackendTemplate
    startup_hints = get_type_hints(
        LitestarAuthConfig.startup_backends,
        localns={
            "StartupBackendTemplate": current_startup_backend_template,
            "UP": ExampleUser,
            "ID": UUID,
        },
    )
    bind_hints = get_type_hints(
        LitestarAuthConfig.bind_request_backends,
        localns={
            "AuthenticationBackend": AuthenticationBackend,
            "StartupBackendTemplate": current_startup_backend_template,
            "UP": ExampleUser,
            "ID": UUID,
        },
    )

    startup_return = startup_hints["return"]
    runtime_return = bind_hints["return"]

    assert get_origin(startup_return) is tuple
    assert get_origin(get_args(startup_return)[0]) is current_startup_backend_template
    assert get_args(startup_return)[1] is Ellipsis
    assert get_origin(runtime_return) is tuple
    assert get_origin(get_args(runtime_return)[0]) is AuthenticationBackend
    assert get_args(runtime_return)[1] is Ellipsis


def test_backend_split_static_types_remain_distinct() -> None:
    """Static typing keeps startup templates separate from runtime backends."""
    startup_backends = _minimal_config().startup_backends()
    runtime_backends = _minimal_config().bind_request_backends(cast("Any", DummySession()))

    assert_type(
        startup_backends,
        tuple[plugin_config_module.StartupBackendTemplate[ExampleUser, UUID], ...],
    )
    assert_type(runtime_backends, tuple[AuthenticationBackend[ExampleUser, UUID], ...])


def test_litestar_auth_config_session_maker_annotation_is_runtime_resolvable() -> None:
    """Runtime type-hint resolution for LitestarAuthConfig includes SessionFactory."""
    hints = get_type_hints(
        LitestarAuthConfig,
        localns={
            "Sequence": Sequence,
            "AuthenticationBackend": AuthenticationBackend,
            "BaseUserManager": BaseUserManager,
            "UserManagerSecurity": UserManagerSecurity,
            "AuthRateLimitConfig": AuthRateLimitConfig,
            "msgspec": msgspec,
        },
    )

    assert hints["session_maker"] == SessionFactory | None


def test_litestar_auth_config_builds_deferred_default_user_db_factory() -> None:
    """Omitting user_db_factory exposes a lazy SQLAlchemy-builder partial without importing the adapter."""
    default_backend = AuthenticationBackend[ExampleUser, UUID](
        name="primary",
        transport=BearerTransport(),
        strategy=cast("Any", InMemoryTokenStrategy(token_prefix="plugin-config")),
    )
    config = LitestarAuthConfig[ExampleUser, UUID](
        backends=[default_backend],
        user_model=ExampleUser,
        user_manager_class=PluginUserManager,
        session_maker=cast(
            "async_sessionmaker[AsyncSession]",
            assert_structural_session_factory(DummySessionMaker()),
        ),
        user_manager_security=UserManagerSecurity[UUID](
            verification_token_secret="x" * 32,
            reset_password_token_secret="y" * 32,
        ),
    )

    assert config.user_db_factory is None
    resolved_factory = config.resolve_user_db_factory()
    assert isinstance(resolved_factory, partial)
    assert resolved_factory.func is plugin_config_module._build_default_user_db
    assert resolved_factory.keywords == {"user_model": ExampleUser}


def test_uses_bundled_database_token_models_detects_manual_db_backend_with_bundled_models() -> None:
    """Bundled DB-token models still trigger startup bootstrap for manual backend assembly."""
    from litestar_auth.authentication.strategy.db import DatabaseTokenStrategy  # noqa: PLC0415

    strategy = DatabaseTokenStrategy(session=cast("Any", object()), token_hash_secret="x" * 40)
    backend = AuthenticationBackend[ExampleUser, UUID](
        name="database",
        transport=BearerTransport(),
        strategy=cast("Any", strategy),
    )
    config = _minimal_config(backends=[backend])

    assert strategy.access_token_model is AccessToken
    assert strategy.refresh_token_model is RefreshToken
    assert plugin_config_module._uses_bundled_database_token_models(config) is True


def test_is_database_token_strategy_instance_returns_false_when_module_not_loaded(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The lazy isinstance check returns False when the DB-strategy module is absent from sys.modules.

    This guards the lazy-import contract: ``import litestar_auth`` must not pull the
    SQLAlchemy adapter, so before any DB strategy has been instantiated the helper
    must report False without forcing the module to load.
    """
    fake_modules = {
        name: module
        for name, module in plugin_config_module.sys.modules.items()
        if name != "litestar_auth.authentication.strategy.db"
    }
    monkeypatch.setattr(plugin_config_module.sys, "modules", fake_modules)

    assert plugin_config_module._is_database_token_strategy_instance(object()) is False


def test_is_bundled_token_model_returns_false_when_module_not_loaded(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The bundled-model identity check returns False when the db_models module is absent from sys.modules.

    Mirrors the lazy-import contract for the bundled token model classes: when no
    code has imported ``litestar_auth.authentication.strategy.db_models`` yet, no
    object can be the bundled class, so the helper must short-circuit to False
    without forcing the import.
    """
    fake_modules = {
        name: module
        for name, module in plugin_config_module.sys.modules.items()
        if name != "litestar_auth.authentication.strategy.db_models"
    }
    monkeypatch.setattr(plugin_config_module.sys, "modules", fake_modules)

    assert plugin_config_module._is_bundled_token_model(object(), attribute_name="AccessToken") is False


def test_resolve_user_manager_factory_returns_explicit_factory_when_configured() -> None:
    """Explicit user_manager_factory overrides the module default builder."""
    factory = cast("Any", lambda **kwargs: kwargs["config"].user_manager_class(kwargs["user_db"], backends=()))
    config = _minimal_config()
    config.user_manager_factory = factory

    assert resolve_user_manager_factory(config) is factory


def test_resolve_user_manager_factory_defaults_to_build_user_manager() -> None:
    """Configs without an override use the module-level default builder."""
    config = _minimal_config()

    assert resolve_user_manager_factory(config) is plugin_config_module.build_user_manager


def _invalid_db_session_config_kwargs(invalid_db_session_key: str) -> dict[str, Any]:
    """Build kwargs for LitestarAuthConfig with an invalid ``db_session_dependency_key``.

    Returns:
        Keyword arguments dict suitable for ``LitestarAuthConfig(**kwargs)``.
    """
    user_db = InMemoryUserDatabase([])
    default_backend = AuthenticationBackend[ExampleUser, UUID](
        name="primary",
        transport=BearerTransport(),
        strategy=cast("Any", InMemoryTokenStrategy(token_prefix="plugin-config")),
    )
    return {
        "backends": [default_backend],
        "user_model": ExampleUser,
        "user_manager_class": PluginUserManager,
        "session_maker": cast(
            "async_sessionmaker[AsyncSession]",
            assert_structural_session_factory(DummySessionMaker()),
        ),
        "user_db_factory": lambda _session: user_db,
        "user_manager_security": UserManagerSecurity[UUID](
            verification_token_secret="x" * 32,
            reset_password_token_secret="y" * 32,
        ),
        "db_session_dependency_key": invalid_db_session_key,
    }


@pytest.mark.parametrize(
    "invalid_db_session_key",
    ["", "with space", "123abc", "for", "class", "return"],
)
def test_litestar_auth_config_rejects_invalid_db_session_dependency_key(
    invalid_db_session_key: str,
) -> None:
    """db_session_dependency_key must be a valid non-keyword identifier at construction."""
    with pytest.raises(ValueError, match="db_session_dependency_key must be a valid Python identifier"):
        LitestarAuthConfig[ExampleUser, UUID](**_invalid_db_session_config_kwargs(invalid_db_session_key))


def test_litestar_auth_config_rejects_invalid_login_identifier() -> None:
    """Unknown login_identifier values fail at construction with ConfigurationError."""
    user_db = InMemoryUserDatabase([])
    default_backend = AuthenticationBackend[ExampleUser, UUID](
        name="primary",
        transport=BearerTransport(),
        strategy=cast("Any", InMemoryTokenStrategy(token_prefix="plugin-config")),
    )
    with pytest.raises(plugin_config_module.ConfigurationError, match=r"Invalid login_identifier"):
        LitestarAuthConfig[ExampleUser, UUID](
            backends=[default_backend],
            user_model=ExampleUser,
            user_manager_class=PluginUserManager,
            session_maker=cast(
                "async_sessionmaker[AsyncSession]",
                assert_structural_session_factory(DummySessionMaker()),
            ),
            user_db_factory=lambda _session: user_db,
            user_manager_security=UserManagerSecurity[UUID](
                verification_token_secret="x" * 32,
                reset_password_token_secret="y" * 32,
            ),
            login_identifier=cast("Any", "phone"),
        )


def test_require_session_maker_raises_value_error_when_session_maker_missing() -> None:
    """require_session_maker raises ValueError with a task-agnostic message."""
    config = _minimal_config()
    config.session_maker = None

    with pytest.raises(ValueError, match="LitestarAuth requires session_maker\\."):
        require_session_maker(config)
