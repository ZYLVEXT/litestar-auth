"""Unit tests for plugin config dataclasses and builder helpers."""

from __future__ import annotations

import importlib
from collections.abc import Callable, Sequence
from datetime import timedelta
from functools import partial
from typing import TYPE_CHECKING, Any, Literal, cast, get_type_hints
from uuid import UUID

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
    user_manager_accepts_id_parser,
    user_manager_accepts_login_identifier,
    user_manager_accepts_password_validator,
    user_manager_accepts_security,
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
from litestar_auth.totp import SecurityWarning
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
        user_manager_security=user_manager_security,
        user_manager_kwargs={
            "verification_token_secret": "x" * 32,
            "reset_password_token_secret": "y" * 32,
        },
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
    assert config.totp_require_replay_protection is True
    assert config.totp_enable_requires_password is True


def test_oauth_config_defaults_match_expected_values() -> None:
    """OAuthConfig exposes stable defaults for optional settings."""
    config = OAuthConfig()

    assert config.oauth_cookie_secure is True
    assert config.oauth_providers is None
    assert config.oauth_associate_by_email is False
    assert config.include_oauth_associate is False
    assert config.oauth_associate_providers is None
    assert not config.oauth_associate_redirect_base_url
    assert config.oauth_token_encryption_key is None


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
        user_manager_kwargs={
            "verification_token_secret": "x" * 32,
            "reset_password_token_secret": "y" * 32,
        },
    )

    preset = config.database_token_auth
    assert preset is not None
    assert not hasattr(preset, "session")
    assert preset.token_hash_secret == "x" * 40
    assert preset.max_age == timedelta(minutes=5)
    assert preset.refresh_max_age == timedelta(hours=12)
    assert preset.token_bytes == configured_token_bytes
    assert preset.accept_legacy_plaintext_tokens is True

    backend = config.resolve_backends()[0]
    assert backend.name == "database"
    assert isinstance(backend.transport, BearerTransport)
    current_strategy_module = importlib.import_module("litestar_auth.authentication.strategy")
    assert isinstance(backend.strategy, current_strategy_module.DatabaseTokenStrategy)
    assert backend.strategy.max_age == timedelta(minutes=5)
    assert backend.strategy.refresh_max_age == timedelta(hours=12)
    assert backend.strategy.token_bytes == configured_token_bytes
    assert backend.strategy.accept_legacy_plaintext_tokens is True
    assert require_session_maker(config) is session_maker


def test_request_scoped_database_token_session_proxy_requires_bound_session() -> None:
    """DB-token preset session proxy fails closed until LitestarAuth binds a request session."""
    reset_token = plugin_config_module._DATABASE_TOKEN_REQUEST_SESSION.set(None)
    try:
        proxy_session = plugin_config_module.resolve_database_token_strategy_session()

        with pytest.raises(RuntimeError, match="requires a LitestarAuth-managed request session"):
            _ = cast("Any", proxy_session).marker
    finally:
        plugin_config_module._DATABASE_TOKEN_REQUEST_SESSION.reset(reset_token)


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
            user_manager_kwargs={
                "verification_token_secret": "x" * 32,
                "reset_password_token_secret": "y" * 32,
            },
        )


def test_resolve_backends_rejects_post_init_mixing_of_preset_and_manual_backends() -> None:
    """`resolve_backends()` fails closed if callers mutate the config into an invalid mixed state."""
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
        user_manager_kwargs={
            "verification_token_secret": "x" * 32,
            "reset_password_token_secret": "y" * 32,
        },
    )
    config.backends = [
        AuthenticationBackend[ExampleUser, UUID](
            name="primary",
            transport=BearerTransport(),
            strategy=cast("Any", InMemoryTokenStrategy(token_prefix="plugin-config")),
        ),
    ]

    with pytest.raises(ValueError, match=r"database_token_auth=\.\.\. or backends=\.\.\., not both"):
        config.resolve_backends()


def test_user_manager_accepts_password_validator_prefers_explicit_class_attribute() -> None:
    """Explicit subclass metadata overrides constructor introspection for password validators."""

    class _ManagerWithExplicitFlag(PluginUserManager):
        accepts_password_validator = False

        def __init__(self, user_db: object, **kwargs: object) -> None:
            del user_db, kwargs

    assert user_manager_accepts_password_validator(_ManagerWithExplicitFlag) is False


def test_user_manager_accepts_password_validator_detects_kwargs_fallback() -> None:
    """Legacy managers using ``**kwargs`` still opt into password validators."""

    class _ManagerWithKwargs:
        def __init__(self, user_db: object, **kwargs: object) -> None:
            del user_db, kwargs

    assert user_manager_accepts_password_validator(cast("Any", _ManagerWithKwargs)) is True


def test_user_manager_accepts_password_validator_inherits_explicit_class_attribute_from_intermediate_base() -> None:
    """Inherited password-validator opt-outs should outrank kwargs-only signature fallback."""

    class _IntermediatePasswordValidatorOptOutManager(PluginUserManager):
        accepts_password_validator = False

        def __init__(self, user_db: object, **kwargs: object) -> None:
            super().__init__(cast("Any", user_db), **cast("Any", kwargs))

    class _ConcretePasswordValidatorOptOutManager(_IntermediatePasswordValidatorOptOutManager):
        pass

    assert user_manager_accepts_password_validator(_ConcretePasswordValidatorOptOutManager) is False


def test_user_manager_accepts_login_identifier_prefers_explicit_class_attribute() -> None:
    """Explicit subclass metadata overrides constructor introspection for login identifiers."""

    class _ManagerWithExplicitFlag(PluginUserManager):
        accepts_login_identifier = False

        def __init__(self, user_db: object, **kwargs: object) -> None:
            del user_db, kwargs

    assert user_manager_accepts_login_identifier(_ManagerWithExplicitFlag) is False


def test_user_manager_accepts_login_identifier_inherits_explicit_class_attribute_from_intermediate_base() -> None:
    """Inherited login-identifier opt-outs should outrank kwargs-only signature fallback."""

    class _IntermediateLoginIdentifierOptOutManager(PluginUserManager):
        accepts_login_identifier = False

        def __init__(self, user_db: object, **kwargs: object) -> None:
            super().__init__(cast("Any", user_db), **cast("Any", kwargs))

    class _ConcreteLoginIdentifierOptOutManager(_IntermediateLoginIdentifierOptOutManager):
        pass

    assert user_manager_accepts_login_identifier(_ConcreteLoginIdentifierOptOutManager) is False


def test_user_manager_accepts_login_identifier_detects_kwargs_fallback() -> None:
    """Legacy managers using ``**kwargs`` still opt into login_identifier injection."""

    class _ManagerWithKwargs:
        def __init__(self, user_db: object, **kwargs: object) -> None:
            del user_db, kwargs

    assert user_manager_accepts_login_identifier(cast("Any", _ManagerWithKwargs)) is True


def test_user_manager_accepts_security_detects_constructor_parameter() -> None:
    """Managers with an explicit ``security`` parameter opt into the typed contract."""

    class _ManagerWithSecurity:
        def __init__(self, user_db: object, *, security: object | None = None) -> None:
            del user_db, security

    assert user_manager_accepts_security(cast("Any", _ManagerWithSecurity)) is True


def test_user_manager_accepts_security_prefers_explicit_class_attribute() -> None:
    """Explicit subclass metadata overrides constructor introspection for ``security`` support."""

    class _ManagerWithExplicitFlag(PluginUserManager):
        accepts_security = True

        def __init__(self, user_db: object, **kwargs: object) -> None:
            del user_db, kwargs

    assert user_manager_accepts_security(_ManagerWithExplicitFlag) is True


def test_user_manager_accepts_security_inherits_explicit_class_attribute_from_intermediate_base() -> None:
    """Inherited explicit security metadata should outrank kwargs-only signature fallback."""

    class _IntermediateSecurityOptInManager(PluginUserManager):
        accepts_security = True

        def __init__(self, user_db: object, **kwargs: object) -> None:
            super().__init__(cast("Any", user_db), **cast("Any", kwargs))

    class _ConcreteSecurityOptInManager(_IntermediateSecurityOptInManager):
        pass

    assert user_manager_accepts_security(_ConcreteSecurityOptInManager) is True


def test_user_manager_accepts_security_ignores_base_user_manager_default_for_kwargs_only_subclass() -> None:
    """Kwargs-only wrappers still need an explicit family-level security opt-in."""

    class _KwargsOnlyManager(PluginUserManager):
        def __init__(self, user_db: object, **kwargs: object) -> None:
            super().__init__(cast("Any", user_db), **cast("Any", kwargs))

    assert user_manager_accepts_security(_KwargsOnlyManager) is False


def test_user_manager_accepts_security_requires_explicit_opt_in_for_kwargs_only() -> None:
    """Kwargs-only managers stay on the legacy compatibility path unless they opt in."""

    class _ManagerWithKwargs:
        def __init__(self, user_db: object, **kwargs: object) -> None:
            del user_db, kwargs

    assert user_manager_accepts_security(cast("Any", _ManagerWithKwargs)) is False


def test_user_manager_accepts_security_ignores_base_user_manager_default_after_reload() -> None:
    """Reloading ``litestar_auth.manager`` does not turn base defaults into explicit overrides."""

    class _KwargsOnlyManager(PluginUserManager):
        def __init__(self, user_db: object, **kwargs: object) -> None:
            super().__init__(cast("Any", user_db), **cast("Any", kwargs))

    manager_module = importlib.import_module("litestar_auth.manager")
    importlib.reload(manager_module)

    assert user_manager_accepts_security(_KwargsOnlyManager) is False


def test_user_manager_accepts_id_parser_prefers_explicit_class_attribute() -> None:
    """Explicit subclass metadata overrides constructor introspection for id_parser."""

    class _ManagerWithExplicitFlag(PluginUserManager):
        accepts_id_parser = False

        def __init__(self, user_db: object, **kwargs: object) -> None:
            del user_db, kwargs

    assert user_manager_accepts_id_parser(_ManagerWithExplicitFlag) is False


def test_user_manager_accepts_id_parser_inherits_explicit_class_attribute_from_intermediate_base() -> None:
    """Inherited id_parser opt-outs should outrank kwargs-only signature fallback."""

    class _IntermediateIdParserOptOutManager(PluginUserManager):
        accepts_id_parser = False

        def __init__(self, user_db: object, **kwargs: object) -> None:
            super().__init__(cast("Any", user_db), **cast("Any", kwargs))

    class _ConcreteIdParserOptOutManager(_IntermediateIdParserOptOutManager):
        pass

    assert user_manager_accepts_id_parser(_ConcreteIdParserOptOutManager) is False


def test_user_manager_accepts_id_parser_detects_kwargs_fallback() -> None:
    """Legacy managers using ``**kwargs`` still opt into id_parser injection."""

    class _ManagerWithKwargs:
        def __init__(self, user_db: object, **kwargs: object) -> None:
            del user_db, kwargs

    assert user_manager_accepts_id_parser(cast("Any", _ManagerWithKwargs)) is True


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


def test_resolve_password_validator_returns_default_for_supported_manager() -> None:
    """Managers that accept password_validator receive the built-in default policy."""
    config = _minimal_config()

    validator = resolve_password_validator(config)

    assert validator is not None
    with pytest.raises(ValueError, match=rf"at least {DEFAULT_MINIMUM_PASSWORD_LENGTH}"):
        validator("short")


def test_resolve_password_validator_returns_none_for_legacy_manager_without_support() -> None:
    """Managers that reject password_validator do not receive an implicit validator."""

    class _LegacyManagerWithoutPasswordValidator(PluginUserManager):
        accepts_password_validator = False

        def __init__(
            self,
            user_db: object,
            *,
            verification_token_secret: str,
            reset_password_token_secret: str,
            backends: tuple[object, ...] = (),
        ) -> None:
            super().__init__(
                cast("Any", user_db),
                verification_token_secret=verification_token_secret,
                reset_password_token_secret=reset_password_token_secret,
                backends=backends,
            )

    config = _minimal_config(user_manager_class=_LegacyManagerWithoutPasswordValidator)

    assert resolve_password_validator(config) is None


def test_resolve_password_validator_respects_inherited_opt_out() -> None:
    """Inherited password-validator opt-outs suppress the plugin default validator."""

    class _IntermediatePasswordValidatorOptOutManager(PluginUserManager):
        accepts_password_validator = False

        def __init__(self, user_db: object, **kwargs: object) -> None:
            super().__init__(cast("Any", user_db), **cast("Any", kwargs))

    class _ConcretePasswordValidatorOptOutManager(_IntermediatePasswordValidatorOptOutManager):
        pass

    config = _minimal_config(user_manager_class=_ConcretePasswordValidatorOptOutManager)

    assert resolve_password_validator(config) is None


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
    password_helper = config.build_password_helper()

    def factory(config: LitestarAuthConfig[ExampleUser, UUID]) -> Callable[[str], None]:
        assert config.memoized_default_password_helper() is password_helper
        assert "password_helper" not in config.user_manager_kwargs
        assert config.user_manager_kwargs["verification_token_secret"] == verification_secret
        assert config.user_manager_kwargs["reset_password_token_secret"] == reset_secret
        return partial(require_password_length, minimum_length=minimum_length)

    config.user_manager_kwargs.update(
        {
            "verification_token_secret": verification_secret,
            "reset_password_token_secret": reset_secret,
        },
    )
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


def test_build_user_manager_uses_inherited_accepts_security_for_kwargs_only_manager() -> None:
    """Inherited explicit security support should switch kwargs-only managers to ``security=...``."""

    class _IntermediateSecurityOptInManager(PluginUserManager):
        accepts_security = True

        def __init__(self, user_db: object, **kwargs: object) -> None:
            self.received_manager_kwargs = dict(kwargs)
            super().__init__(cast("Any", user_db), **cast("Any", self.received_manager_kwargs))

    class _ConcreteSecurityOptInManager(_IntermediateSecurityOptInManager):
        pass

    verification_secret = "v" * 32
    reset_secret = "r" * 32
    totp_secret_key = "t" * 32
    config = LitestarAuthConfig[ExampleUser, UUID](
        backends=_minimal_config().backends,
        user_model=ExampleUser,
        user_manager_class=_ConcreteSecurityOptInManager,
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
    """Security-aware constructors receive the typed bundle without fallback kwargs."""

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
        ) -> None:
            self.received_security = security
            super().__init__(
                cast("Any", user_db),
                password_helper=password_helper,
                security=security,
                password_validator=cast("Any", password_validator),
                backends=backends,
                login_identifier=login_identifier,
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


def test_build_user_manager_falls_back_to_legacy_secret_kwargs_for_security_incompatible_manager() -> None:
    """Managers without ``security`` support still receive the legacy compatibility kwargs."""

    class _LegacyManagerWithoutSecurity(PluginUserManager):
        def __init__(  # noqa: PLR0913
            self,
            user_db: object,
            *,
            password_helper: PasswordHelper | None = None,
            password_validator: object | None = None,
            verification_token_secret: str,
            reset_password_token_secret: str,
            totp_secret_key: str | None = None,
            id_parser: type[UUID] | None = None,
            backends: tuple[object, ...] = (),
            login_identifier: Literal["email", "username"] = "email",
        ) -> None:
            self.received_legacy_inputs = {
                "verification_token_secret": verification_token_secret,
                "reset_password_token_secret": reset_password_token_secret,
                "totp_secret_key": totp_secret_key,
                "id_parser": id_parser,
            }
            super().__init__(
                cast("Any", user_db),
                password_helper=password_helper,
                password_validator=cast("Any", password_validator),
                verification_token_secret=verification_token_secret,
                reset_password_token_secret=reset_password_token_secret,
                totp_secret_key=totp_secret_key,
                id_parser=id_parser,
                backends=backends,
                login_identifier=login_identifier,
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

    manager = build_user_manager(
        session=cast("Any", DummySession()),
        user_db=InMemoryUserDatabase([]),
        config=config,
        backends=("bound-backend",),
    )
    typed_manager = cast("Any", manager)

    assert typed_manager.received_legacy_inputs == {
        "verification_token_secret": verification_secret,
        "reset_password_token_secret": reset_secret,
        "totp_secret_key": totp_secret_key,
        "id_parser": UUID,
    }
    assert manager.id_parser is UUID
    assert manager.login_identifier == "username"
    assert manager.backends == ("bound-backend",)


def test_build_user_manager_warns_but_preserves_reused_legacy_secret_roles() -> None:
    """Legacy reused secrets remain source-compatible while warning in production."""
    shared_secret = "shared-plugin-manager-secret-1234567890"
    config = _minimal_config()
    config.user_manager_kwargs.update(
        {
            "verification_token_secret": shared_secret,
            "reset_password_token_secret": shared_secret,
            "totp_secret_key": shared_secret,
        },
    )

    with pytest.warns(SecurityWarning, match="supported production posture"):
        manager = build_user_manager(
            session=cast("Any", DummySession()),
            user_db=InMemoryUserDatabase([]),
            config=config,
        )

    assert manager.verification_token_secret.get_secret_value() == shared_secret
    assert manager.reset_password_token_secret.get_secret_value() == shared_secret
    assert manager.totp_secret_key == shared_secret


def test_build_user_manager_skips_login_identifier_for_legacy_manager_without_support() -> None:
    """Compatibility builders do not inject login_identifier into legacy manager constructors."""

    class _LegacyManagerWithoutLoginIdentifier(PluginUserManager):
        accepts_login_identifier = False

        def __init__(
            self,
            user_db: object,
            *,
            password_validator: object | None = None,
            verification_token_secret: str,
            reset_password_token_secret: str,
            backends: tuple[object, ...] = (),
        ) -> None:
            super().__init__(
                cast("Any", user_db),
                password_validator=cast("Any", password_validator),
                verification_token_secret=verification_token_secret,
                reset_password_token_secret=reset_password_token_secret,
                backends=backends,
            )

    config = _minimal_config(
        login_identifier="username",
        user_manager_class=_LegacyManagerWithoutLoginIdentifier,
    )

    manager = build_user_manager(
        session=cast("Any", DummySession()),
        user_db=InMemoryUserDatabase([]),
        config=config,
    )

    assert manager.login_identifier == "email"


def test_build_user_manager_skips_login_identifier_for_inherited_opt_out() -> None:
    """Inherited login-identifier opt-outs still suppress compatibility kwargs injection."""

    class _IntermediateLoginIdentifierOptOutManager(PluginUserManager):
        accepts_login_identifier = False

        def __init__(self, user_db: object, **kwargs: object) -> None:
            self.received_manager_kwargs = dict(kwargs)
            super().__init__(cast("Any", user_db), **cast("Any", self.received_manager_kwargs))

    class _ConcreteLoginIdentifierOptOutManager(_IntermediateLoginIdentifierOptOutManager):
        pass

    config = _minimal_config(
        login_identifier="username",
        user_manager_class=_ConcreteLoginIdentifierOptOutManager,
    )

    manager = build_user_manager(
        session=cast("Any", DummySession()),
        user_db=InMemoryUserDatabase([]),
        config=config,
    )
    typed_manager = cast("Any", manager)

    assert "login_identifier" not in typed_manager.received_manager_kwargs
    assert manager.login_identifier == "email"


def test_build_user_manager_skips_id_parser_for_legacy_manager_without_support() -> None:
    """Compatibility builders do not inject id_parser into legacy manager constructors."""

    class _LegacyManagerWithoutIdParser(PluginUserManager):
        accepts_id_parser = False

        def __init__(
            self,
            user_db: object,
            *,
            password_validator: object | None = None,
            verification_token_secret: str,
            reset_password_token_secret: str,
            backends: tuple[object, ...] = (),
        ) -> None:
            super().__init__(
                cast("Any", user_db),
                password_validator=cast("Any", password_validator),
                verification_token_secret=verification_token_secret,
                reset_password_token_secret=reset_password_token_secret,
                backends=backends,
            )

    config = _minimal_config(
        id_parser=UUID,
        user_manager_class=_LegacyManagerWithoutIdParser,
    )

    manager = build_user_manager(
        session=cast("Any", DummySession()),
        user_db=InMemoryUserDatabase([]),
        config=config,
    )

    assert manager.id_parser is None


def test_require_session_maker_returns_configured_session_maker() -> None:
    """require_session_maker returns a structurally compatible configured factory unchanged."""
    config = _minimal_config()

    assert require_session_maker(config) is config.session_maker


def test_require_session_maker_annotations_are_runtime_resolvable() -> None:
    """Runtime type-hint resolution for require_session_maker keeps the structural contract intact."""
    hints = get_type_hints(require_session_maker)

    assert hints["return"] is SessionFactory


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
        user_manager_kwargs={
            "verification_token_secret": "x" * 32,
            "reset_password_token_secret": "y" * 32,
        },
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
        "user_manager_kwargs": {
            "verification_token_secret": "x" * 32,
            "reset_password_token_secret": "y" * 32,
        },
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
            user_manager_kwargs={
                "verification_token_secret": "x" * 32,
                "reset_password_token_secret": "y" * 32,
            },
            login_identifier=cast("Any", "phone"),
        )


def test_require_session_maker_raises_value_error_when_session_maker_missing() -> None:
    """require_session_maker raises ValueError with a task-agnostic message."""
    config = _minimal_config()
    config.session_maker = None

    with pytest.raises(ValueError, match="LitestarAuth requires session_maker\\."):
        require_session_maker(config)
