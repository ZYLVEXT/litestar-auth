"""Resolver helpers for plugin configuration."""

from __future__ import annotations

from typing import TYPE_CHECKING, Any, Protocol

from litestar_auth._manager.construction import ManagerConstructorInputs
from litestar_auth._plugin.scoped_session import SessionFactory  # noqa: TC001
from litestar_auth._plugin.security_policy import (
    _describe_totp_secret_storage_policy,
    _PluginSecurityNotice,
)
from litestar_auth._superuser_role import normalize_superuser_role_name
from litestar_auth.exceptions import ConfigurationError
from litestar_auth.types import UserProtocol

if TYPE_CHECKING:
    from collections.abc import Callable

    from sqlalchemy.ext.asyncio import AsyncSession

    from litestar_auth._plugin.config._core import StartupBackendInventory
    from litestar_auth.db.base import BaseUserStore
    from litestar_auth.manager import UserManagerSecurity


class _FeatureRegistryWithInventory[UP: UserProtocol[Any], ID](Protocol):
    """Feature registry surface needed by backend inventory resolution."""

    backend_inventory: StartupBackendInventory[UP, ID]


class _BackendInventoryConfig[UP: UserProtocol[Any], ID](Protocol):
    """Config surface needed by ``resolve_backend_inventory``."""

    def resolve_feature_registry(self) -> _FeatureRegistryWithInventory[UP, ID]:
        """Return the resolved feature registry."""
        # pragma: no cover - Protocol method body - pure type contract


class _TotpSecretPolicyConfig[ID](Protocol):
    """Config surface needed by plugin-managed TOTP secret policy resolution."""

    @property
    def totp_config(self) -> object | None:
        """Return the configured TOTP feature settings."""
        # pragma: no cover - Protocol property body - pure type contract

    @property
    def user_manager_factory(self) -> object | None:
        """Return the custom user-manager factory, when configured."""
        # pragma: no cover - Protocol property body - pure type contract

    @property
    def user_manager_security(self) -> UserManagerSecurity[ID] | None:
        """Return manager-owned security settings, when configured."""
        # pragma: no cover - Protocol property body - pure type contract

    @property
    def id_parser(self) -> Callable[[str], ID] | None:
        """Return the configured ID parser, when configured."""
        # pragma: no cover - Protocol property body - pure type contract


class _SessionMakerConfig(Protocol):
    """Config surface needed by ``require_session_maker``."""

    session_maker: SessionFactory | None


def resolve_backend_inventory[UP: UserProtocol[Any], ID](
    config: _BackendInventoryConfig[UP, ID],
) -> StartupBackendInventory[UP, ID]:
    """Return the resolved backend inventory for ``config``."""
    return config.resolve_feature_registry().backend_inventory


def _build_default_user_db(session: AsyncSession, *, user_model: type[Any]) -> BaseUserStore[Any, Any]:
    """Build a ``SQLAlchemyUserDatabase`` with a deferred adapter import.

    Used by :meth:`LitestarAuthConfig.resolve_user_db_factory` via ``functools.partial`` so the
    SQLAlchemy adapter module is loaded only at first request-scoped call, not at
    configuration time.

    Returns:
        A :class:`~litestar_auth.db.sqlalchemy.SQLAlchemyUserDatabase` bound to ``session``.
    """
    from litestar_auth.db.sqlalchemy import SQLAlchemyUserDatabase  # noqa: PLC0415

    return SQLAlchemyUserDatabase(session, user_model=user_model)


def _resolve_plugin_managed_totp_secret_storage_policy[UP: UserProtocol[Any], ID](
    config: _TotpSecretPolicyConfig[ID],
) -> _PluginSecurityNotice | None:
    """Resolve the TOTP storage policy owned by plugin-managed manager wiring.

    Returns:
        The plugin-managed TOTP storage notice when the plugin owns manager
        secret wiring for the active config, otherwise ``None``.
    """
    if config.totp_config is None:
        return None
    if config.user_manager_factory is not None and config.user_manager_security is None:
        return None
    manager_inputs = ManagerConstructorInputs(
        manager_security=config.user_manager_security,
        id_parser=config.id_parser,
    )
    effective_security = manager_inputs.effective_security
    return _describe_totp_secret_storage_policy(
        totp_secret_key=effective_security.totp_secret_key or None,
        keyring_configured=effective_security.totp_secret_keyring is not None,
    )


def _normalize_config_superuser_role_name(role_name: str) -> str:
    """Normalize the config-owned superuser role name as a configuration error.

    Returns:
        The normalized role name.

    Raises:
        ConfigurationError: If the value is not a non-empty role name string.
    """
    try:
        return normalize_superuser_role_name(role_name)
    except (TypeError, ValueError) as exc:
        raise ConfigurationError(str(exc)) from exc


def require_session_maker[UP: UserProtocol[Any], ID](
    config: _SessionMakerConfig,
) -> SessionFactory:
    """Return the configured session factory or fail when it is omitted.

    Raises:
        ValueError: When ``session_maker`` is omitted.
    """
    maker = config.session_maker
    if maker is None:
        msg = "LitestarAuth requires session_maker."
        raise ValueError(msg)
    return maker
