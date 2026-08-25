"""Unit tests for ``litestar_auth._plugin.user_manager_builder``."""

from __future__ import annotations

import warnings
from typing import TYPE_CHECKING, Any, Literal, cast
from uuid import UUID

import pytest
from cryptography.fernet import Fernet

import litestar_auth._plugin.config as plugin_config_module
import litestar_auth._plugin.user_manager_builder as user_manager_builder_module
from litestar_auth.authentication.backend import AuthenticationBackend
from litestar_auth.authentication.strategy._jwt_denylist import InMemoryJWTDenylistStore
from litestar_auth.authentication.transport.cookie import CookieTransport
from litestar_auth.config import DEFAULT_MINIMUM_PASSWORD_LENGTH, require_password_length
from litestar_auth.manager import FernetKeyringConfig, UserManagerSecurity
from litestar_auth.password import PasswordHelper
from litestar_auth.plugin import LitestarAuthConfig
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
    import inspect

    from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

pytestmark = pytest.mark.unit

CUSTOM_VALIDATOR_MIN_LENGTH_OFFSET = 4
FACTORY_VALIDATOR_MIN_LENGTH_OFFSET = 8


def _generate_fernet_key() -> str:
    """Generate and return a valid Fernet key for builder tests.

    Returns:
        A valid Fernet key.
    """
    return Fernet.generate_key().decode()


def _minimal_config(
    *,
    user_manager_class: type[Any] | None = None,
    user_manager_security: UserManagerSecurity[UUID] | None = None,
    id_parser: type[UUID] | None = None,
    login_identifier: Literal["email", "username"] = "email",
    superuser_role_name: str = "superuser",
) -> LitestarAuthConfig[ExampleUser, UUID]:
    """Build a minimal current-shape config for user-manager-builder tests.

    Returns:
        A config instance using the post-deprecation manager-construction surface.
    """
    default_backend = AuthenticationBackend[ExampleUser, UUID](
        name="primary",
        transport=CookieTransport(allow_insecure_cookie_auth=True),
        strategy=cast("Any", InMemoryTokenStrategy(token_prefix="builder-tests")),
    )
    return LitestarAuthConfig[ExampleUser, UUID](
        backends=[default_backend],
        user_model=ExampleUser,
        user_manager_class=user_manager_class or PluginUserManager,
        session_maker=cast(
            "async_sessionmaker[AsyncSession]",
            assert_structural_session_factory(DummySessionMaker()),
        ),
        user_db_factory=lambda _session: InMemoryUserDatabase([]),
        user_manager_security=user_manager_security
        or UserManagerSecurity[UUID](
            verification_token_secret="157261932c2bdecb9f6c6ee849a24e3a979a9bf46cf50e99a739b4cd5545cebe",
            reset_password_token_secret="6a04e4ffd25866a9cce15600e9ff4bd0865b84e7474f6c7eb2d75fef3c0a81d8",
        ),
        id_parser=id_parser,
        login_identifier=login_identifier,
        superuser_role_name=superuser_role_name,
    )


def test_config_module_does_not_reexport_user_manager_builder_helpers() -> None:
    """Builder helpers are owned by ``user_manager_builder``, not re-exported by config."""
    assert user_manager_builder_module.build_user_manager.__module__ == "litestar_auth._plugin.user_manager_builder"
    for name in (
        "_build_default_user_manager_contract",
        "_build_default_user_manager_validation_kwargs",
        "build_user_manager",
        "default_password_validator_factory",
        "resolve_password_validator",
        "resolve_user_manager_factory",
    ):
        assert not hasattr(plugin_config_module, name)


def test_account_token_store_constructor_detection(monkeypatch: pytest.MonkeyPatch) -> None:
    """Replay-store injection requires an explicitly named parameter, not **kwargs."""

    class _ExplicitManager:
        def __init__(self, *, account_token_denylist_store: object) -> None:
            """Declare explicit replay-store support for signature inspection."""

    class _KwargsManager:
        def __init__(self, **kwargs: object) -> None:
            """Declare catch-all constructor support for signature inspection."""

    class _UnsupportedManager:
        pass

    accepts = user_manager_builder_module._manager_accepts_account_token_store
    assert accepts(_ExplicitManager)
    # A bare **kwargs can swallow the keyword without wiring the store, so it
    # must not count as acceptance.
    assert not accepts(_KwargsManager)
    assert not accepts(_UnsupportedManager)
    assert not accepts(None)

    def _raise_uninspectable(_manager_class: object) -> inspect.Signature:
        raise ValueError

    monkeypatch.setattr(user_manager_builder_module.inspect, "signature", _raise_uninspectable)
    assert not accepts(_ExplicitManager)


def test_build_kwargs_warns_when_store_cannot_be_injected_into_kwargs_only_manager() -> None:
    """A configured store that cannot be injected emits SecurityWarning instead of silent skip."""

    class _KwargsOnlyManager:
        def __init__(self, **kwargs: object) -> None:
            """Catch-all constructor that does not declare the replay-store parameter."""

    config = _minimal_config(user_manager_class=_KwargsOnlyManager)
    config.account_token_denylist_store = InMemoryJWTDenylistStore()
    contract = user_manager_builder_module._DefaultUserManagerBuilderContract(
        config=config,
        password_helper=PasswordHelper(),
        password_validator=None,
        backends=(),
    )

    with pytest.warns(user_manager_builder_module.SecurityWarning, match="was NOT injected"):
        kwargs = contract.build_kwargs()

    assert "account_token_denylist_store" not in kwargs


def test_build_kwargs_omits_store_when_none_is_configured() -> None:
    """No store configured means neither injection nor the missing-injection warning."""

    class _NoStoreParamManager:
        def __init__(self, *, unsafe_testing: bool = False) -> None:
            """Manager without an account_token_denylist_store parameter."""

    config = _minimal_config(user_manager_class=_NoStoreParamManager)
    config.account_token_denylist_store = None
    contract = user_manager_builder_module._DefaultUserManagerBuilderContract(
        config=config,
        password_helper=PasswordHelper(),
        password_validator=None,
        backends=(),
    )

    with warnings.catch_warnings(record=True) as caught:
        warnings.simplefilter("always")
        kwargs = contract.build_kwargs()

    assert "account_token_denylist_store" not in kwargs
    assert not any(issubclass(w.category, user_manager_builder_module.SecurityWarning) for w in caught)


def test_default_builder_contract_materializes_canonical_kwargs() -> None:
    """The default builder now forwards only the canonical security-based contract."""

    def password_validator(password: str) -> None:
        require_password_length(
            password,
            DEFAULT_MINIMUM_PASSWORD_LENGTH + CUSTOM_VALIDATOR_MIN_LENGTH_OFFSET,
        )

    password_helper = PasswordHelper()
    totp_keyring = FernetKeyringConfig(active_key_id="current", keys={"current": _generate_fernet_key()})
    config = _minimal_config(
        user_manager_security=UserManagerSecurity[UUID](
            verification_token_secret="157261932c2bdecb9f6c6ee849a24e3a979a9bf46cf50e99a739b4cd5545cebe",
            reset_password_token_secret="6a04e4ffd25866a9cce15600e9ff4bd0865b84e7474f6c7eb2d75fef3c0a81d8",
            totp_secret_keyring=totp_keyring,
        ),
        id_parser=UUID,
        login_identifier="username",
    )
    contract = user_manager_builder_module._build_default_user_manager_contract(
        config,
        password_helper=password_helper,
        password_validator=password_validator,
        backends=("bound-backend",),
    )

    kwargs = contract.build_kwargs()

    assert set(kwargs) == {
        "backends",
        "login_identifier",
        "password_helper",
        "password_validator",
        "security",
        "superuser_role_name",
        "unsafe_testing",
    }
    assert kwargs["password_helper"] is password_helper
    assert kwargs["password_validator"] is password_validator
    assert kwargs["backends"] == ("bound-backend",)
    assert kwargs["login_identifier"] == "username"
    assert kwargs["superuser_role_name"] == "superuser"
    assert kwargs["unsafe_testing"] is False
    security = kwargs["security"]
    assert security is not None
    assert security.verification_token_secret == "157261932c2bdecb9f6c6ee849a24e3a979a9bf46cf50e99a739b4cd5545cebe"
    assert security.reset_password_token_secret == "6a04e4ffd25866a9cce15600e9ff4bd0865b84e7474f6c7eb2d75fef3c0a81d8"
    assert security.totp_secret_keyring is totp_keyring
    assert security.id_parser is UUID


def test_validation_kwargs_keep_password_validator_slot_without_runtime_factory() -> None:
    """Startup validation keeps the canonical keyword surface without executing factories."""
    config = _minimal_config(id_parser=UUID)

    kwargs = user_manager_builder_module._build_default_user_manager_validation_kwargs(
        config,
        backends=("bound-backend",),
    )

    assert kwargs["password_validator"] is None
    assert kwargs["backends"] == ("bound-backend",)
    assert kwargs["login_identifier"] == "email"
    assert kwargs["superuser_role_name"] == "superuser"
    assert kwargs["unsafe_testing"] is False
    security = kwargs["security"]
    assert security is not None
    assert security.id_parser is UUID


def test_resolve_password_validator_prefers_factory_over_default() -> None:
    """The simplified builder resolves validators only from the explicit factory or default."""

    def factory_validator(password: str) -> None:
        require_password_length(
            password,
            DEFAULT_MINIMUM_PASSWORD_LENGTH + FACTORY_VALIDATOR_MIN_LENGTH_OFFSET,
        )

    config = _minimal_config()
    config.password_validator_factory = lambda _config: factory_validator

    assert user_manager_builder_module.resolve_password_validator(config) is factory_validator


def test_resolve_password_validator_returns_default_when_factory_is_unset() -> None:
    """The default plugin password validator remains the fallback for the default builder."""
    config = _minimal_config()

    validator = user_manager_builder_module.resolve_password_validator(config)

    assert validator is not None
    with pytest.raises(ValueError, match=rf"at least {DEFAULT_MINIMUM_PASSWORD_LENGTH}"):
        validator("short")


def test_build_user_manager_passes_only_canonical_kwargs() -> None:
    """Runtime manager construction uses the same straight-line canonical keyword surface."""

    class _KwargsWrapperManager(PluginUserManager):
        def __init__(self, user_db: object, **kwargs: object) -> None:
            self.received_manager_kwargs = dict(kwargs)
            self.received_security = cast("UserManagerSecurity[UUID]", kwargs["security"])
            super().__init__(cast("Any", user_db), **cast("Any", self.received_manager_kwargs))

    totp_keyring = FernetKeyringConfig(active_key_id="current", keys={"current": _generate_fernet_key()})
    raw_superuser_role_name = " Admin "
    normalized_superuser_role_name = raw_superuser_role_name.strip().lower()
    config = _minimal_config(
        user_manager_class=_KwargsWrapperManager,
        user_manager_security=UserManagerSecurity[UUID](
            verification_token_secret="157261932c2bdecb9f6c6ee849a24e3a979a9bf46cf50e99a739b4cd5545cebe",
            reset_password_token_secret="6a04e4ffd25866a9cce15600e9ff4bd0865b84e7474f6c7eb2d75fef3c0a81d8",
            totp_secret_keyring=totp_keyring,
        ),
        id_parser=UUID,
        login_identifier="username",
        superuser_role_name=raw_superuser_role_name,
    )

    manager = user_manager_builder_module.build_user_manager(
        session=cast("Any", DummySession()),
        user_db=InMemoryUserDatabase([]),
        config=config,
        backends=("bound-backend",),
    )
    typed_manager = cast("_KwargsWrapperManager", manager)

    assert set(typed_manager.received_manager_kwargs) == {
        "backends",
        "login_identifier",
        "password_helper",
        "password_validator",
        "security",
        "superuser_role_name",
        "unsafe_testing",
    }
    assert isinstance(
        typed_manager.received_manager_kwargs["password_helper"],
        PasswordHelper,
    )
    assert typed_manager.received_manager_kwargs["password_validator"] is not None
    assert typed_manager.received_manager_kwargs["backends"] == ("bound-backend",)
    assert typed_manager.received_manager_kwargs["login_identifier"] == "username"
    assert typed_manager.received_manager_kwargs["superuser_role_name"] == normalized_superuser_role_name
    assert typed_manager.received_manager_kwargs["superuser_role_name"] != raw_superuser_role_name
    assert typed_manager.received_manager_kwargs["unsafe_testing"] is False
    assert typed_manager.received_security.id_parser is UUID
    assert typed_manager.received_security.totp_secret_keyring is totp_keyring


def test_build_user_manager_rejects_missing_manager_class_without_custom_factory() -> None:
    """Default builder fails closed when neither manager path owns construction."""
    config = _minimal_config()
    config.user_manager_class = None

    with pytest.raises(
        user_manager_builder_module.ConfigurationError,
        match="user_manager_class must be configured",
    ):
        user_manager_builder_module.build_user_manager(
            session=cast("Any", DummySession()),
            user_db=InMemoryUserDatabase([]),
            config=config,
            backends=(),
        )
