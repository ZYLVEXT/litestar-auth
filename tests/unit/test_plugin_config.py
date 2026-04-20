"""Unit tests for plugin config dataclasses and builder helpers."""

from __future__ import annotations

import importlib
import re
import sys
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
    build_user_manager,
    default_password_validator_factory,
    require_session_maker,
    resolve_password_validator,
    resolve_user_manager_factory,
)
from litestar_auth._plugin.oauth_contract import _build_oauth_route_registration_contract
from litestar_auth._plugin.scoped_session import SessionFactory
from litestar_auth._plugin.user_manager_builder import _DefaultUserManagerBuilderContract
from litestar_auth.authentication.backend import AuthenticationBackend
from litestar_auth.authentication.strategy.db_models import AccessToken, RefreshToken
from litestar_auth.authentication.transport.bearer import BearerTransport
from litestar_auth.authentication.transport.cookie import CookieTransport
from litestar_auth.config import DEFAULT_MINIMUM_PASSWORD_LENGTH, require_password_length
from litestar_auth.exceptions import InvalidPasswordError
from litestar_auth.manager import BaseUserManager, UserManagerSecurity
from litestar_auth.password import PasswordHelper
from litestar_auth.plugin import LitestarAuth, LitestarAuthConfig
from litestar_auth.ratelimit import AuthRateLimitConfig
from litestar_auth.schemas import UserCreate
from litestar_auth.types import LoginIdentifier
from tests.e2e.conftest import assert_structural_session_factory
from tests.integration.test_orchestrator import (
    DummySession,
    DummySessionMaker,
    ExampleUser,
    InMemoryTokenStrategy,
    InMemoryUserDatabase,
    PluginUserManager,
)

# Canonical substring from ``_raise_startup_only_database_token_runtime_error`` (database_token.py).
_DB_TOKEN_STARTUP_ONLY_FAIL_CLOSED = re.escape("LitestarAuthConfig.resolve_backends(session)")

if TYPE_CHECKING:
    from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

    from litestar_auth.config import OAuthProviderConfig
    from litestar_auth.db.base import BaseUserStore

pytestmark = pytest.mark.unit


def _current_startup_backend_template_type() -> type[Any]:
    """Resolve the current StartupBackendTemplate class to survive cross-test module reloads.

    Returns:
        The current StartupBackendTemplate type.
    """
    return cast("type[Any]", importlib.import_module("litestar_auth._plugin.config").StartupBackendTemplate)


def _current_authentication_backend_type() -> type[Any]:
    """Resolve the current AuthenticationBackend class to survive cross-test module reloads.

    Returns:
        The current AuthenticationBackend type.
    """
    return cast("type[Any]", importlib.import_module("litestar_auth.authentication.backend").AuthenticationBackend)


def _current_database_token_strategy_type() -> type[Any]:
    """Resolve the current DB-token strategy class to survive cross-test module reloads.

    Returns:
        The current DatabaseTokenStrategy type.
    """
    return cast("type[Any]", importlib.import_module("litestar_auth.authentication.strategy.db").DatabaseTokenStrategy)


def _current_password_helper_type() -> type[Any]:
    """Resolve the current PasswordHelper class to survive cross-test module reloads.

    Returns:
        The current PasswordHelper type.
    """
    return cast("type[Any]", importlib.import_module("litestar_auth.password").PasswordHelper)


def _current_oauth_provider_config_type() -> type[Any]:
    """Resolve the current OAuthProviderConfig class to survive cross-test module reloads.

    Returns:
        The current OAuthProviderConfig type.
    """
    return cast("type[Any]", importlib.import_module("litestar_auth.config").OAuthProviderConfig)


def _oauth_provider(*, name: str, client: object) -> OAuthProviderConfig:
    """Build an OAuthProviderConfig using the current runtime class.

    Returns:
        The current-runtime OAuthProviderConfig instance.
    """
    oauth_provider_config_type = _current_oauth_provider_config_type()
    return oauth_provider_config_type(name=name, client=client)


def test_plugin_config_module_executes_under_coverage() -> None:
    """Reload the module in-test so coverage records module and dataclass execution."""
    reloaded_module = importlib.reload(plugin_config_module)

    assert reloaded_module.LitestarAuthConfig.__name__ == LitestarAuthConfig.__name__
    assert reloaded_module.DatabaseTokenAuthConfig.__name__ == DatabaseTokenAuthConfig.__name__
    assert reloaded_module.OAuthConfig.__name__ == OAuthConfig.__name__


def test_oauth_contract_module_executes_under_coverage() -> None:
    """Reload the OAuth route contract module so coverage records module-level execution."""
    oauth_contract_module = importlib.import_module("litestar_auth._plugin.oauth_contract")
    importlib.reload(oauth_contract_module)


def test_default_builder_constructor_mismatch_diagnostic_matches_security_bundle_contract() -> None:
    """Constructor-mismatch text describes security=UserManagerSecurity, not standalone id_parser."""
    msg = _DefaultUserManagerBuilderContract.build_constructor_mismatch_message(
        "ExampleManager",
        TypeError("boom"),
    )
    assert "security=UserManagerSecurity" in msg
    assert "not a standalone id_parser=" in msg
    assert "directly instead" not in msg


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
    assert plugin_config_module.DbSessionDependencyKey.__name__ == "DbSessionDependencyKey"
    assert dataclass_fields["db_session_dependency_key"].type == "DbSessionDependencyKey"
    assert "db_session_dependency_provided_externally" in dataclass_fields


def test_litestar_auth_config_declares_login_identifier_field() -> None:
    """The plugin config exposes login_identifier with a safe default."""
    dataclass_fields = LitestarAuthConfig.__dataclass_fields__

    assert "login_identifier" in dataclass_fields
    assert dataclass_fields["login_identifier"].type == "LoginIdentifier"
    assert dataclass_fields["login_identifier"].default == "email"
    assert frozenset(get_args(LoginIdentifier.__value__)) == plugin_config_module._VALID_LOGIN_IDENTIFIERS


def test_litestar_auth_config_login_identifier_defaults_to_email() -> None:
    """Default login mode is email."""
    config = _minimal_config()

    assert config.login_identifier == "email"


def test_litestar_auth_config_direct_construction_preserves_user_and_id_types() -> None:
    """Direct construction preserves the configured user and ID generic parameters."""
    default_backend = AuthenticationBackend[ExampleUser, UUID](
        name="primary",
        transport=BearerTransport(),
        strategy=cast("Any", InMemoryTokenStrategy(token_prefix="plugin-config-create")),
    )
    user_manager_security = UserManagerSecurity[UUID](
        verification_token_secret="x" * 32,
        reset_password_token_secret="y" * 32,
    )

    config = LitestarAuthConfig[ExampleUser, UUID](
        backends=[default_backend],
        user_model=ExampleUser,
        user_manager_class=PluginUserManager,
        user_manager_security=user_manager_security,
    )

    assert_type(config, LitestarAuthConfig[ExampleUser, UUID])
    assert config.user_model is ExampleUser
    assert config.user_manager_class is PluginUserManager
    assert config.backends == [default_backend]
    assert config.user_manager_security is user_manager_security


def test_litestar_auth_config_direct_default_manager_path_builds_expected_config() -> None:
    """Direct construction supports the plugin-owned default manager path."""
    default_backend = AuthenticationBackend[ExampleUser, UUID](
        name="primary",
        transport=BearerTransport(),
        strategy=cast("Any", InMemoryTokenStrategy(token_prefix="plugin-config-default-manager")),
    )
    user_manager_security = UserManagerSecurity[UUID](
        verification_token_secret="x" * 32,
        reset_password_token_secret="y" * 32,
    )
    session_maker = assert_structural_session_factory(DummySessionMaker())

    config = LitestarAuthConfig[ExampleUser, UUID](
        backends=[default_backend],
        user_model=ExampleUser,
        user_manager_class=PluginUserManager,
        user_manager_security=user_manager_security,
        session_maker=cast("async_sessionmaker[AsyncSession]", session_maker),
        include_users=True,
        login_identifier="username",
    )

    assert_type(config, LitestarAuthConfig[ExampleUser, UUID])
    assert config.user_model is ExampleUser
    assert config.user_manager_class is PluginUserManager
    assert config.user_manager_security is user_manager_security
    assert config.user_manager_factory is None
    assert config.session_maker is session_maker
    assert config.user_db_factory is None
    assert config.backends == [default_backend]
    assert config.include_users is True
    assert config.login_identifier == "username"


def test_litestar_auth_config_direct_default_manager_path_runs_post_init_validation() -> None:
    """Direct construction goes through the normal dataclass validation path."""
    user_manager_security = UserManagerSecurity[UUID](
        verification_token_secret="x" * 32,
        reset_password_token_secret="y" * 32,
        id_parser=UUID,
    )

    config = LitestarAuthConfig[ExampleUser, UUID](
        user_model=ExampleUser,
        user_manager_class=PluginUserManager,
        user_manager_security=user_manager_security,
    )

    assert config.id_parser is UUID

    with pytest.raises(plugin_config_module.ConfigurationError, match="Invalid login_identifier"):
        LitestarAuthConfig[ExampleUser, UUID](
            user_model=ExampleUser,
            user_manager_class=PluginUserManager,
            login_identifier=cast("Any", "phone"),
        )


def test_litestar_auth_config_direct_default_manager_path_preserves_user_and_id_type_parameters() -> None:
    """Direct construction lets type checkers keep the configured user and ID parameters."""
    config = LitestarAuthConfig[ExampleUser, UUID](
        user_model=ExampleUser,
        user_manager_class=PluginUserManager,
        user_manager_security=UserManagerSecurity[UUID](
            verification_token_secret="x" * 32,
            reset_password_token_secret="y" * 32,
        ),
        id_parser=UUID,
    )

    assert_type(config, LitestarAuthConfig[ExampleUser, UUID])
    assert_type(config.user_model, type[ExampleUser])
    assert_type(config.user_manager_class, type[BaseUserManager[ExampleUser, UUID]] | None)
    assert config.user_model is ExampleUser
    assert config.user_manager_class is PluginUserManager
    assert config.id_parser is UUID


def test_litestar_auth_config_direct_custom_manager_factory_path_builds_expected_config() -> None:
    """Direct construction supports the caller-owned manager factory path."""

    def custom_manager_factory(
        *,
        session: AsyncSession,
        user_db: BaseUserStore[ExampleUser, UUID],
        config: LitestarAuthConfig[ExampleUser, UUID],
        backends: tuple[object, ...] = (),
        skip_reuse_warning: bool = False,
    ) -> BaseUserManager[ExampleUser, UUID]:
        msg = "factory should not be invoked during config construction"
        raise AssertionError(msg)

    default_backend = AuthenticationBackend[ExampleUser, UUID](
        name="primary",
        transport=BearerTransport(),
        strategy=cast("Any", InMemoryTokenStrategy(token_prefix="plugin-config-custom-manager-factory")),
    )
    user_manager_security = UserManagerSecurity[UUID](
        verification_token_secret="x" * 32,
        reset_password_token_secret="y" * 32,
    )

    config = LitestarAuthConfig[ExampleUser, UUID](
        user_model=ExampleUser,
        user_manager_factory=custom_manager_factory,
        backends=[default_backend],
        user_manager_security=user_manager_security,
        login_identifier="username",
    )

    assert_type(config, LitestarAuthConfig[ExampleUser, UUID])
    assert_type(config.user_manager_class, type[BaseUserManager[ExampleUser, UUID]] | None)
    assert config.user_model is ExampleUser
    assert config.user_manager_class is None
    assert config.user_manager_factory is custom_manager_factory
    assert config.backends == [default_backend]
    assert config.user_manager_security is user_manager_security
    assert config.login_identifier == "username"


def test_litestar_auth_config_direct_custom_manager_factory_invokes_factory_for_request_scope() -> None:
    """Direct construction wires the factory used for request-scoped manager construction."""
    captured: dict[str, object] = {}
    user_db = InMemoryUserDatabase([])

    def custom_manager_factory(
        *,
        session: AsyncSession,
        user_db: BaseUserStore[ExampleUser, UUID],
        config: LitestarAuthConfig[ExampleUser, UUID],
        backends: tuple[object, ...] = (),
        skip_reuse_warning: bool = False,
    ) -> BaseUserManager[ExampleUser, UUID]:
        captured.update(
            session=session,
            user_db=user_db,
            config=config,
            backends=backends,
            skip_reuse_warning=skip_reuse_warning,
        )
        return PluginUserManager(
            user_db,
            security=cast("UserManagerSecurity[UUID]", config.user_manager_security),
            backends=backends,
            skip_reuse_warning=skip_reuse_warning,
        )

    default_backend = AuthenticationBackend[ExampleUser, UUID](
        name="primary",
        transport=BearerTransport(),
        strategy=cast("Any", InMemoryTokenStrategy(token_prefix="plugin-config-custom-manager-request")),
    )
    config = LitestarAuthConfig[ExampleUser, UUID](
        user_model=ExampleUser,
        user_manager_factory=custom_manager_factory,
        backends=[default_backend],
        session_maker=cast(
            "async_sessionmaker[AsyncSession]",
            assert_structural_session_factory(DummySessionMaker()),
        ),
        user_db_factory=lambda _session: user_db,
        user_manager_security=UserManagerSecurity[UUID](
            verification_token_secret="x" * 32,
            reset_password_token_secret="y" * 32,
        ),
    )
    plugin = LitestarAuth(config)
    session = cast("Any", DummySession())

    manager = plugin._build_user_manager(session)

    assert isinstance(manager, PluginUserManager)
    assert captured["session"] is session
    assert captured["config"] is config
    assert len(cast("tuple[object, ...]", captured["backends"])) == 1
    assert captured["user_db"] is not user_db


async def test_litestar_auth_config_direct_custom_manager_factory_wrong_return_type_surfaces_error() -> None:
    """A factory that returns a non-manager fails when the request-scoped manager contract is used."""

    def custom_manager_factory(
        *,
        session: AsyncSession,
        user_db: BaseUserStore[ExampleUser, UUID],
        config: LitestarAuthConfig[ExampleUser, UUID],
        backends: tuple[object, ...] = (),
        skip_reuse_warning: bool = False,
    ) -> BaseUserManager[ExampleUser, UUID]:
        del skip_reuse_warning
        return cast("BaseUserManager[ExampleUser, UUID]", object())

    config = LitestarAuthConfig[ExampleUser, UUID](
        user_model=ExampleUser,
        user_manager_factory=custom_manager_factory,
        backends=[
            AuthenticationBackend[ExampleUser, UUID](
                name="primary",
                transport=BearerTransport(),
                strategy=cast("Any", InMemoryTokenStrategy(token_prefix="plugin-config-wrong-manager")),
            ),
        ],
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
    plugin = LitestarAuth(config)
    manager = plugin._build_user_manager(cast("Any", DummySession()))

    with pytest.raises(AttributeError, match="get"):
        await manager.get(uuid4())


@pytest.mark.parametrize("invalid_factory", [object()])
def test_litestar_auth_config_direct_custom_manager_factory_rejects_missing_or_noncallable_factory(
    invalid_factory: object,
) -> None:
    """Direct construction fails fast when the custom factory contract is invalid."""
    with pytest.raises(plugin_config_module.ConfigurationError, match="user_manager_factory must be callable"):
        LitestarAuthConfig[ExampleUser, UUID](
            user_model=ExampleUser,
            user_manager_factory=cast("Any", invalid_factory),
        )


def test_litestar_auth_config_rejects_direct_class_and_factory_conflict() -> None:
    """Direct construction cannot combine the default manager class path with a custom factory."""

    def custom_manager_factory(
        *,
        session: AsyncSession,
        user_db: BaseUserStore[ExampleUser, UUID],
        config: LitestarAuthConfig[ExampleUser, UUID],
        backends: tuple[object, ...] = (),
        skip_reuse_warning: bool = False,
    ) -> BaseUserManager[ExampleUser, UUID]:
        msg = "factory should not be invoked during config construction"
        raise AssertionError(msg)

    with pytest.raises(
        plugin_config_module.ConfigurationError,
        match="user_manager_class and user_manager_factory are mutually exclusive",
    ):
        LitestarAuthConfig[ExampleUser, UUID](
            user_model=ExampleUser,
            user_manager_class=PluginUserManager,
            user_manager_factory=custom_manager_factory,
        )


def test_litestar_auth_config_direct_manager_paths_run_post_init_once(monkeypatch: pytest.MonkeyPatch) -> None:
    """Direct construction runs dataclass post-init validation once per config."""
    config_cls = plugin_config_module.LitestarAuthConfig
    expected_validation_calls = 2
    backend_validation_calls = 0
    original_validate_backend_configuration = config_cls._validate_backend_configuration

    def counted_validate_backend_configuration(self: LitestarAuthConfig[ExampleUser, UUID]) -> None:
        nonlocal backend_validation_calls
        backend_validation_calls += 1
        original_validate_backend_configuration(self)

    def custom_manager_factory(
        *,
        session: AsyncSession,
        user_db: BaseUserStore[ExampleUser, UUID],
        config: LitestarAuthConfig[ExampleUser, UUID],
        backends: tuple[object, ...] = (),
        skip_reuse_warning: bool = False,
    ) -> BaseUserManager[ExampleUser, UUID]:
        msg = "factory should not be invoked during config construction"
        raise AssertionError(msg)

    monkeypatch.setattr(
        config_cls,
        "_validate_backend_configuration",
        counted_validate_backend_configuration,
    )

    default_config = config_cls[ExampleUser, UUID](
        user_model=ExampleUser,
        user_manager_class=PluginUserManager,
    )
    custom_config = config_cls[ExampleUser, UUID](
        user_model=ExampleUser,
        user_manager_factory=custom_manager_factory,
    )

    assert backend_validation_calls == expected_validation_calls
    assert default_config.user_manager_factory is None
    assert custom_config.user_manager_class is None


@pytest.mark.parametrize(
    ("manager_kwargs", "invalid_kwargs", "expected_error", "expected_message"),
    [
        (
            {"user_manager_class": PluginUserManager},
            {"login_identifier": "phone"},
            plugin_config_module.ConfigurationError,
            "Invalid login_identifier",
        ),
        (
            {"user_manager_factory": lambda **_: cast("Any", object())},
            {"db_session_dependency_key": "not-valid"},
            ValueError,
            "valid Python identifier",
        ),
        (
            {"user_manager_class": PluginUserManager},
            {
                "backends": [
                    AuthenticationBackend[ExampleUser, UUID](
                        name="manual",
                        transport=BearerTransport(),
                        strategy=cast("Any", InMemoryTokenStrategy(token_prefix="post-init-conflict")),
                    ),
                ],
                "database_token_auth": DatabaseTokenAuthConfig(token_hash_secret="x" * 40),
            },
            ValueError,
            "database_token_auth",
        ),
    ],
)
def test_litestar_auth_config_direct_manager_paths_run_each_post_init_validation_once(
    monkeypatch: pytest.MonkeyPatch,
    manager_kwargs: dict[str, object],
    invalid_kwargs: dict[str, object],
    expected_error: type[Exception],
    expected_message: str,
) -> None:
    """Direct construction does not miss or duplicate post-init validation failures."""
    config_cls = plugin_config_module.LitestarAuthConfig
    backend_validation_calls = 0
    original_validate_backend_configuration = config_cls._validate_backend_configuration

    def counted_validate_backend_configuration(self: LitestarAuthConfig[ExampleUser, UUID]) -> None:
        nonlocal backend_validation_calls
        backend_validation_calls += 1
        original_validate_backend_configuration(self)

    def custom_manager_factory(
        *,
        session: AsyncSession,
        user_db: BaseUserStore[ExampleUser, UUID],
        config: LitestarAuthConfig[ExampleUser, UUID],
        backends: tuple[object, ...] = (),
        skip_reuse_warning: bool = False,
    ) -> BaseUserManager[ExampleUser, UUID]:
        msg = "factory should not be invoked during config construction"
        raise AssertionError(msg)

    monkeypatch.setattr(
        config_cls,
        "_validate_backend_configuration",
        counted_validate_backend_configuration,
    )
    common_kwargs: dict[str, object] = {"user_model": ExampleUser, **manager_kwargs, **invalid_kwargs}
    if "user_manager_factory" in manager_kwargs:
        common_kwargs["user_manager_factory"] = custom_manager_factory

    with pytest.raises(expected_error, match=expected_message):
        config_cls[ExampleUser, UUID](**cast("Any", common_kwargs))

    assert backend_validation_calls == 1


def test_litestar_auth_config_rejects_both_user_manager_class_and_factory() -> None:
    """Direct construction rejects ambiguous manager ownership."""

    def custom_manager_factory(
        *,
        session: AsyncSession,
        user_db: BaseUserStore[ExampleUser, UUID],
        config: LitestarAuthConfig[ExampleUser, UUID],
        backends: tuple[object, ...] = (),
        skip_reuse_warning: bool = False,
    ) -> BaseUserManager[ExampleUser, UUID]:
        msg = "factory should not be invoked during config construction"
        raise AssertionError(msg)

    with pytest.raises(
        plugin_config_module.ConfigurationError,
        match="user_manager_class and user_manager_factory are mutually exclusive",
    ):
        LitestarAuthConfig[ExampleUser, UUID](
            user_model=ExampleUser,
            user_manager_class=PluginUserManager,
            user_manager_factory=custom_manager_factory,
        )


def test_litestar_auth_config_resolve_password_helper_memoizes_default_helper() -> None:
    """Config exposes one memoized helper for plugin and app-owned password work."""
    config = _minimal_config()

    first = config.resolve_password_helper()
    second = config.resolve_password_helper()

    assert first is second
    assert first.password_hash.hashers[0].__class__.__name__ == "Argon2Hasher"
    assert first.password_hash.hashers[1].__class__.__name__ == "BcryptHasher"


def test_litestar_auth_config_resolve_password_helper_survives_password_module_reload() -> None:
    """Default helper resolution should use the current PasswordHelper after a module reload."""
    config = _minimal_config()
    password_module = importlib.import_module("litestar_auth.password")

    importlib.reload(password_module)
    helper = config.resolve_password_helper()

    assert isinstance(helper, _current_password_helper_type())


def test_litestar_auth_config_resolve_password_helper_preserves_explicit_helper_override() -> None:
    """Config-level helper resolution keeps deliberate typed helper injection unchanged."""
    explicit_password_helper = PasswordHelper()
    config = _minimal_config(
        user_manager_security=UserManagerSecurity[UUID](
            verification_token_secret="x" * 32,
            reset_password_token_secret="y" * 32,
            password_helper=explicit_password_helper,
        ),
    )

    assert config.resolve_password_helper() is explicit_password_helper


def test_litestar_auth_config_resolve_password_helper_uses_typed_security_helper() -> None:
    """Direct config construction resolves password helpers from the typed security bundle."""
    typed_password_helper = PasswordHelper()

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
            verification_token_secret="x" * 32,
            reset_password_token_secret="y" * 32,
            password_helper=typed_password_helper,
        ),
    )

    assert config.resolve_password_helper() is typed_password_helper


def test_build_user_manager_uses_typed_password_helper_from_security() -> None:
    """Plugin-owned manager construction mirrors config password-helper resolution."""
    typed_password_helper = PasswordHelper()

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
            verification_token_secret="x" * 32,
            reset_password_token_secret="y" * 32,
            password_helper=typed_password_helper,
        ),
    )

    manager = build_user_manager(
        session=cast("Any", DummySession()),
        user_db=InMemoryUserDatabase([]),
        config=config,
    )

    assert manager.password_helper is typed_password_helper


def test_litestar_auth_config_exposes_only_canonical_password_and_backend_accessors() -> None:
    """Removed alias methods: only resolve_* / get_* surfaces exist on the config class."""
    config = _minimal_config()
    assert not hasattr(LitestarAuthConfig, "build_password_helper")
    assert not hasattr(LitestarAuthConfig, "memoized_default_password_helper")
    assert not hasattr(LitestarAuthConfig, "startup_backends")
    assert not hasattr(LitestarAuthConfig, "bind_request_backends")
    session = cast("Any", DummySession())
    helper = config.resolve_password_helper()
    assert helper is config.get_default_password_helper()
    assert config.resolve_startup_backends()
    assert config.resolve_backends(session)


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


def test_oauth_provider_config_constructed_with_keywords() -> None:
    """OAuthProviderConfig supports keyword construction for IDE-friendly wiring."""
    client = object()
    oauth_provider_config_type = _current_oauth_provider_config_type()
    entry = oauth_provider_config_type(name="github", client=client)
    assert entry.name == "github"
    assert entry.client is client


def test_oauth_provider_config_coerce_is_idempotent() -> None:
    """Coercing an already-normalized entry returns the same instance."""
    oauth_provider_config_type = _current_oauth_provider_config_type()
    original = oauth_provider_config_type(name="x", client=object())
    assert oauth_provider_config_type.coerce(original) is original


def test_oauth_provider_config_coerce_rejects_reload_stale_instance() -> None:
    """Reloaded config modules reject provider entries built before the reload."""
    config_module = importlib.import_module("litestar_auth.config")
    stale_provider_type = cast("type[Any]", config_module.OAuthProviderConfig)
    client = object()
    stale_entry = stale_provider_type(name="github", client=client)

    reloaded_module = importlib.reload(config_module)
    current_provider_type = cast("type[Any]", reloaded_module.OAuthProviderConfig)

    with pytest.raises(TypeError, match="OAuth provider entries must be"):
        current_provider_type.coerce(stale_entry)


def test_oauth_provider_config_coerce_rejects_invalid_shape() -> None:
    """Invalid provider inventory items raise a clear TypeError."""
    oauth_provider_config_type = _current_oauth_provider_config_type()
    with pytest.raises(TypeError, match="OAuth provider entries must be"):
        oauth_provider_config_type.coerce(cast("Any", ("only-one",)))


def test_oauth_provider_config_coerce_rejects_non_instance() -> None:
    """Only real OAuthProviderConfig instances are accepted."""
    oauth_provider_config_type = _current_oauth_provider_config_type()
    with pytest.raises(TypeError, match="OAuth provider entries must be"):
        oauth_provider_config_type.coerce(object())


def test_oauth_route_registration_contract_accepts_explicit_provider_entries() -> None:
    """Plugin boundary keeps explicit OAuthProviderConfig entries intact."""
    gh = object()
    oauth_provider_config_type = _current_oauth_provider_config_type()
    contract = _build_oauth_route_registration_contract(
        auth_path="/auth/",
        oauth_config=OAuthConfig(
            oauth_providers=[
                oauth_provider_config_type(name="github", client=gh),
                oauth_provider_config_type(name="gitlab", client=object()),
            ],
            oauth_redirect_base_url="https://app.example/auth/",
        ),
    )
    assert [p.name for p in contract.providers] == ["github", "gitlab"]
    assert contract.providers[0].client is gh


def test_oauth_route_registration_contract_with_no_oauth_config() -> None:
    """When ``oauth_config`` is omitted, the contract matches the empty OAuth surface."""
    contract = _build_oauth_route_registration_contract(auth_path="/auth", oauth_config=None)

    assert contract.has_configured_providers is False
    assert contract.has_plugin_owned_login_routes is False
    assert contract.has_plugin_owned_associate_routes is False
    assert contract.login_path == "/auth/oauth"
    assert contract.associate_path == "/auth/associate"
    assert contract.redirect_base_url is None


def test_oauth_route_registration_contract_omits_redirects_without_plugin_owned_routes() -> None:
    """Without providers, the plugin-owned OAuth callback bases stay absent."""
    contract = _build_oauth_route_registration_contract(
        auth_path="/auth",
        oauth_config=OAuthConfig(),
    )

    assert contract.has_configured_providers is False
    assert contract.has_plugin_owned_login_routes is False
    assert contract.has_plugin_owned_associate_routes is False
    assert contract.login_redirect_base_url is None
    assert contract.associate_redirect_base_url is None


def test_oauth_route_registration_contract_derives_login_and_associate_redirect_bases() -> None:
    """A shared OAuth redirect base fans out to login and associate callback prefixes."""
    contract = _build_oauth_route_registration_contract(
        auth_path="/auth/",
        oauth_config=OAuthConfig(
            oauth_providers=[_oauth_provider(name="github", client=object())],
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
            oauth_providers=[
                _oauth_provider(name="github", client=object()),
                _oauth_provider(name="gitlab", client=object()),
            ],
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
            oauth_providers=[_oauth_provider(name="github", client=object())],
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
                oauth_providers=[_oauth_provider(name="github", client=object())],
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
                oauth_providers=[_oauth_provider(name="github", client=object())],
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

    backend = config.resolve_startup_backends()[0]
    database_token_strategy_type = _current_database_token_strategy_type()
    assert isinstance(backend, _current_startup_backend_template_type())
    assert backend.name == "database"
    assert isinstance(backend.transport, BearerTransport)
    assert isinstance(backend.strategy, database_token_strategy_type)
    assert backend.strategy.max_age == timedelta(minutes=5)
    assert backend.strategy.refresh_max_age == timedelta(hours=12)
    assert backend.strategy.token_bytes == configured_token_bytes
    assert backend.strategy.accept_legacy_plaintext_tokens is True
    assert require_session_maker(config) is session_maker


def test_resolve_startup_backends_wrap_manual_backends_in_startup_templates() -> None:
    """Manual backends are exposed through the startup-only template type."""
    backend = AuthenticationBackend[ExampleUser, UUID](
        name="manual",
        transport=BearerTransport(),
        strategy=cast("Any", InMemoryTokenStrategy(token_prefix="manual")),
    )
    config = _minimal_config(backends=[backend])

    startup_backend = config.resolve_startup_backends()[0]

    assert isinstance(startup_backend, _current_startup_backend_template_type())
    assert startup_backend.name == backend.name
    assert startup_backend.transport is backend.transport
    assert startup_backend.strategy is backend.strategy


def test_openapi_security_helpers_follow_the_configured_backend_inventory() -> None:
    """App-owned route helpers derive schemes and OR requirements from startup backends."""
    config = _minimal_config(
        backends=[
            AuthenticationBackend[ExampleUser, UUID](
                name="bearer",
                transport=BearerTransport(),
                strategy=cast("Any", InMemoryTokenStrategy(token_prefix="bearer-openapi")),
            ),
            AuthenticationBackend[ExampleUser, UUID](
                name="cookie",
                transport=CookieTransport(cookie_name="auth_cookie"),
                strategy=cast("Any", InMemoryTokenStrategy(token_prefix="cookie-openapi")),
            ),
        ],
    )

    schemes = config.resolve_openapi_security_schemes()
    requirements = config.resolve_openapi_security_requirements()

    assert set(schemes) == {"bearer", "cookie"}
    assert schemes["bearer"].type == "http"
    assert schemes["bearer"].scheme == "Bearer"
    assert schemes["cookie"].type == "apiKey"
    assert schemes["cookie"].name == "auth_cookie"
    assert requirements == [{"bearer": []}, {"cookie": []}]


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

    startup_backend = config.resolve_startup_backends()[0]

    assert "session" not in vars(cast("Any", startup_backend.strategy))


def test_resolve_database_token_strategy_session_without_session_fails_closed() -> None:
    """The legacy helper still returns a placeholder that raises the canonical runtime error."""
    startup_session = plugin_config_module.resolve_database_token_strategy_session()

    with pytest.raises(RuntimeError, match=_DB_TOKEN_STARTUP_ONLY_FAIL_CLOSED):
        _ = startup_session.execute


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
    startup_backend = config.resolve_startup_backends()[0]
    user = ExampleUser(id=uuid4())

    with pytest.raises(RuntimeError, match=_DB_TOKEN_STARTUP_ONLY_FAIL_CLOSED):
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
    startup_strategy = cast("Any", config.resolve_startup_backends()[0].strategy)
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
        with pytest.raises(RuntimeError, match=_DB_TOKEN_STARTUP_ONLY_FAIL_CLOSED):
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
    database_token_strategy_type = _current_database_token_strategy_type()

    assert backend.name == "opaque-db"
    assert isinstance(backend.strategy, database_token_strategy_type)
    assert backend.strategy.session is active_session
    assert backend.strategy.refresh_max_age == timedelta(days=14)
    assert backend.strategy.accept_legacy_plaintext_tokens is True


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


def test_resolve_backends_binds_manual_backends_without_database_token_preset() -> None:
    """`resolve_backends(session)` keeps explicit manual backends available at runtime."""

    class _SessionAwareStrategy(InMemoryTokenStrategy):
        def __init__(self, *, token_prefix: str) -> None:
            super().__init__(token_prefix=token_prefix)
            self.sessions_seen: list[object] = []

        def with_session(self, session: object) -> _SessionAwareStrategy:
            self.sessions_seen.append(session)
            return self

    strategy = _SessionAwareStrategy(token_prefix="manual")
    backend = AuthenticationBackend[ExampleUser, UUID](
        name="manual",
        transport=BearerTransport(),
        strategy=cast("Any", strategy),
    )
    config = _minimal_config(backends=[backend])
    active_session = DummySession()

    runtime_backends = config.resolve_backends(cast("Any", active_session))

    assert runtime_backends == (backend,)
    assert strategy.sessions_seen == [active_session]


def test_resolve_backends_realizes_database_token_preset_from_request_session() -> None:
    """`resolve_backends(session)` also realizes the canonical DB-token preset."""
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
    active_session = DummySession()
    authentication_backend_type = _current_authentication_backend_type()
    database_token_strategy_type = _current_database_token_strategy_type()

    startup_backend = config.resolve_startup_backends()[0]
    runtime_backends = config.resolve_backends(cast("Any", active_session))

    assert isinstance(startup_backend, _current_startup_backend_template_type())
    assert len(runtime_backends) == 1
    assert isinstance(runtime_backends[0], authentication_backend_type)
    assert runtime_backends[0].name == "database"
    assert runtime_backends[0] is not startup_backend
    assert isinstance(startup_backend.strategy, database_token_strategy_type)
    assert isinstance(runtime_backends[0].strategy, database_token_strategy_type)
    assert cast("Any", runtime_backends[0].strategy).session is active_session


def test_resolve_backends_preserves_manual_backend_inventory_order() -> None:
    """Manual backends bind sessions in the same order through the canonical runtime accessor."""

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

    runtime_backends = config.resolve_backends(cast("Any", active_session))

    assert runtime_backends == (primary_backend, secondary_backend)
    assert primary_strategy.sessions_seen == [active_session]
    assert secondary_strategy.sessions_seen == [active_session]


def test_resolve_backends_preserves_database_token_runtime_contract_details() -> None:
    """The DB-token preset still exposes startup templates plus request-scoped runtime backends."""
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
    authentication_backend_type = _current_authentication_backend_type()
    database_token_strategy_type = _current_database_token_strategy_type()

    startup_backend = config.resolve_startup_backends()[0]
    runtime_backends = config.resolve_backends(cast("Any", active_session))

    assert isinstance(startup_backend, _current_startup_backend_template_type())
    assert len(runtime_backends) == 1
    assert isinstance(runtime_backends[0], authentication_backend_type)
    assert runtime_backends[0].name == "opaque-db"
    assert runtime_backends[0] is not startup_backend
    assert isinstance(startup_backend.strategy, database_token_strategy_type)
    assert isinstance(runtime_backends[0].strategy, database_token_strategy_type)
    assert cast("Any", runtime_backends[0].strategy).session is active_session
    assert cast("Any", runtime_backends[0].strategy).refresh_max_age == timedelta(days=14)
    assert cast("Any", runtime_backends[0].strategy).accept_legacy_plaintext_tokens is True


def test_resolve_startup_backends_reject_post_init_mixing_of_preset_and_manual_backends() -> None:
    """`resolve_startup_backends()` fails closed if callers mutate the config into an invalid mixed state."""
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
        config.resolve_startup_backends()


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


def test_build_user_manager_uses_factory_password_validator_and_config_login_identifier() -> None:
    """The default builder uses the configured validator factory and login identifier."""

    def explicit_password_validator(password: str) -> None:
        require_password_length(password, 10)

    user_db = InMemoryUserDatabase([])
    config = _minimal_config(login_identifier="username")
    config.password_validator_factory = lambda _config: explicit_password_validator

    manager = build_user_manager(
        session=cast("Any", DummySession()),
        user_db=user_db,
        config=config,
        backends=("bound-backend",),
    )

    assert manager.password_validator is explicit_password_validator
    assert manager.login_identifier == "username"
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

    assert config.get_default_password_helper() is None

    manager = build_user_manager(
        session=cast("Any", DummySession()),
        user_db=InMemoryUserDatabase([]),
        config=config,
    )

    hashed_password = manager.received_password_helper.hash("shared-password")

    assert manager.received_password_helper.verify("shared-password", hashed_password) is True
    assert manager.password_helper is manager.received_password_helper
    assert config.get_default_password_helper() is manager.received_password_helper


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
    password_helper = config.resolve_password_helper()

    def factory(config: LitestarAuthConfig[ExampleUser, UUID]) -> Callable[[str], None]:
        assert config.get_default_password_helper() is password_helper
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
            password_helper=password_helper,
        ),
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
            password_helper=PasswordHelper(),
        ),
        login_identifier="username",
    )

    manager = build_user_manager(
        session=cast("Any", DummySession()),
        user_db=InMemoryUserDatabase([]),
        config=config,
        backends=("bound-backend",),
    )
    typed_manager = manager

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
            password_helper=PasswordHelper(),
        ),
        id_parser=UUID,
        login_identifier="username",
    )

    manager = build_user_manager(
        session=cast("Any", DummySession()),
        user_db=InMemoryUserDatabase([]),
        config=config,
        backends=("bound-backend",),
    )
    typed_manager = manager

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
                security=UserManagerSecurity[UUID](
                    verification_token_secret=verification_token_secret,
                    reset_password_token_secret=reset_password_token_secret,
                ),
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
            password_helper=PasswordHelper(),
        ),
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


def test_build_user_manager_preserves_configured_unsafe_testing_flag() -> None:
    """The default builder forwards the top-level unsafe-testing flag unchanged."""

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
    config.unsafe_testing = True

    manager = build_user_manager(
        session=cast("Any", DummySession()),
        user_db=InMemoryUserDatabase([]),
        config=config,
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
        LitestarAuthConfig.resolve_startup_backends,
        localns={
            "StartupBackendTemplate": current_startup_backend_template,
            "UP": ExampleUser,
            "ID": UUID,
        },
    )
    bind_hints = get_type_hints(
        LitestarAuthConfig.resolve_backends,
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
    startup_backends = _minimal_config().resolve_startup_backends()
    runtime_backends = _minimal_config().resolve_backends(cast("Any", DummySession()))

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
        name: module for name, module in sys.modules.items() if name != "litestar_auth.authentication.strategy.db"
    }
    monkeypatch.setattr(sys, "modules", fake_modules)

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
        for name, module in sys.modules.items()
        if name != "litestar_auth.authentication.strategy.db_models"
    }
    monkeypatch.setattr(sys, "modules", fake_modules)

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
