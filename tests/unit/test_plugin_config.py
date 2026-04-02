"""Unit tests for plugin config dataclasses and builder helpers."""

from __future__ import annotations

import importlib
from typing import Any, Literal, cast
from uuid import UUID

import pytest

import litestar_auth._plugin.config as plugin_config_module
from litestar_auth._plugin.config import (
    OAuthConfig,
    TotpConfig,
    build_user_manager,
    default_password_validator_factory,
    require_session_maker,
    resolve_password_validator,
    resolve_user_manager_factory,
    user_manager_accepts_login_identifier,
    user_manager_accepts_password_validator,
)
from litestar_auth.authentication.backend import AuthenticationBackend
from litestar_auth.authentication.transport.bearer import BearerTransport
from litestar_auth.config import DEFAULT_MINIMUM_PASSWORD_LENGTH
from litestar_auth.manager import require_password_length
from litestar_auth.plugin import LitestarAuthConfig
from tests.integration.test_orchestrator import (
    DummySession,
    DummySessionMaker,
    ExampleUser,
    InMemoryTokenStrategy,
    InMemoryUserDatabase,
    PluginUserManager,
)

pytestmark = pytest.mark.unit


def test_plugin_config_module_executes_under_coverage() -> None:
    """Reload the module in-test so coverage records module and dataclass execution."""
    reloaded_module = importlib.reload(plugin_config_module)

    assert reloaded_module.LitestarAuthConfig.__name__ == LitestarAuthConfig.__name__
    assert reloaded_module.OAuthConfig.__name__ == OAuthConfig.__name__


def _minimal_config(
    *,
    backends: list[AuthenticationBackend[ExampleUser, UUID]] | None = None,
    include_users: bool = False,
    totp_config: TotpConfig | None = None,
    user_manager_class: type[Any] | None = None,
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
        session_maker=cast("Any", DummySessionMaker()),
        user_db_factory=lambda _session: user_db,
        user_manager_kwargs={
            "verification_token_secret": "x" * 32,
            "reset_password_token_secret": "y" * 32,
        },
        include_users=include_users,
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


def test_user_manager_accepts_login_identifier_prefers_explicit_class_attribute() -> None:
    """Explicit subclass metadata overrides constructor introspection for login identifiers."""

    class _ManagerWithExplicitFlag(PluginUserManager):
        accepts_login_identifier = False

        def __init__(self, user_db: object, **kwargs: object) -> None:
            del user_db, kwargs

    assert user_manager_accepts_login_identifier(_ManagerWithExplicitFlag) is False


def test_user_manager_accepts_login_identifier_detects_kwargs_fallback() -> None:
    """Legacy managers using ``**kwargs`` still opt into login_identifier injection."""

    class _ManagerWithKwargs:
        def __init__(self, user_db: object, **kwargs: object) -> None:
            del user_db, kwargs

    assert user_manager_accepts_login_identifier(cast("Any", _ManagerWithKwargs)) is True


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


def test_require_session_maker_returns_configured_session_maker() -> None:
    """require_session_maker returns the configured factory unchanged on the success path."""
    config = _minimal_config()

    assert require_session_maker(config) is config.session_maker


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
        "session_maker": cast("Any", DummySessionMaker()),
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
            session_maker=cast("Any", DummySessionMaker()),
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
