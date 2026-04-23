"""Unit tests for ``litestar_auth._plugin.user_manager_builder``."""

from __future__ import annotations

import importlib
from typing import TYPE_CHECKING, Any, Literal, cast
from uuid import UUID

import pytest

import litestar_auth._plugin.config as plugin_config_module
import litestar_auth._plugin.user_manager_builder as user_manager_builder_module
from litestar_auth.authentication.backend import AuthenticationBackend
from litestar_auth.authentication.transport.bearer import BearerTransport
from litestar_auth.config import DEFAULT_MINIMUM_PASSWORD_LENGTH, require_password_length
from litestar_auth.manager import UserManagerSecurity
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
    from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

pytestmark = pytest.mark.unit


def _current_password_helper_type() -> type[Any]:
    """Resolve the current PasswordHelper class to survive cross-test module reloads.

    Returns:
        The current PasswordHelper type.
    """
    return cast("type[Any]", importlib.import_module("litestar_auth.password").PasswordHelper)


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
        transport=BearerTransport(),
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
            verification_token_secret="v" * 32,
            reset_password_token_secret="r" * 32,
        ),
        id_parser=id_parser,
        login_identifier=login_identifier,
        superuser_role_name=superuser_role_name,
    )


def test_config_reexports_delegate_to_user_manager_builder_module() -> None:
    """Public and internal symbols re-exported from config match the implementation module."""
    assert plugin_config_module.build_user_manager is user_manager_builder_module.build_user_manager
    assert plugin_config_module.resolve_password_validator is user_manager_builder_module.resolve_password_validator
    assert plugin_config_module.resolve_user_manager_factory is user_manager_builder_module.resolve_user_manager_factory
    assert (
        plugin_config_module._build_default_user_manager_contract
        is user_manager_builder_module._build_default_user_manager_contract
    )


def test_default_builder_contract_materializes_canonical_kwargs() -> None:
    """The default builder now forwards only the canonical security-based contract."""

    def password_validator(password: str) -> None:
        require_password_length(password, DEFAULT_MINIMUM_PASSWORD_LENGTH + 4)

    password_helper = object()
    config = _minimal_config(
        user_manager_security=UserManagerSecurity[UUID](
            verification_token_secret="v" * 32,
            reset_password_token_secret="r" * 32,
            totp_secret_key="t" * 32,
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
    assert kwargs["security"].verification_token_secret == "v" * 32
    assert kwargs["security"].reset_password_token_secret == "r" * 32
    assert kwargs["security"].totp_secret_key == "t" * 32
    assert kwargs["security"].id_parser is UUID


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
    assert kwargs["security"].id_parser is UUID


def test_resolve_password_validator_prefers_factory_over_default() -> None:
    """The simplified builder resolves validators only from the explicit factory or default."""

    def factory_validator(password: str) -> None:
        require_password_length(password, DEFAULT_MINIMUM_PASSWORD_LENGTH + 8)

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

    config = _minimal_config(
        user_manager_class=_KwargsWrapperManager,
        user_manager_security=UserManagerSecurity[UUID](
            verification_token_secret="v" * 32,
            reset_password_token_secret="r" * 32,
            totp_secret_key="t" * 32,
        ),
        id_parser=UUID,
        login_identifier="username",
        superuser_role_name=" Admin ",
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
        _current_password_helper_type(),
    )
    assert typed_manager.received_manager_kwargs["password_validator"] is not None
    assert typed_manager.received_manager_kwargs["backends"] == ("bound-backend",)
    assert typed_manager.received_manager_kwargs["login_identifier"] == "username"
    assert typed_manager.received_manager_kwargs["superuser_role_name"] == "admin"
    assert typed_manager.received_manager_kwargs["unsafe_testing"] is False
    assert typed_manager.received_security.id_parser is UUID
    assert typed_manager.received_security.totp_secret_key == "t" * 32


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
        )
