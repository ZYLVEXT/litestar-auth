"""User-manager construction helpers for :class:`~litestar_auth._plugin.config.LitestarAuthConfig`."""

from __future__ import annotations

from dataclasses import dataclass
from functools import partial
from typing import TYPE_CHECKING, Any

from litestar_auth._manager.construction import ManagerConstructorInputs
from litestar_auth._plugin.config import UserManagerFactory  # noqa: TC001
from litestar_auth.config import DEFAULT_MINIMUM_PASSWORD_LENGTH, require_password_length
from litestar_auth.exceptions import ConfigurationError
from litestar_auth.types import UserProtocol

if TYPE_CHECKING:
    from collections.abc import Callable

    from sqlalchemy.ext.asyncio import AsyncSession

    from litestar_auth._plugin.config import LitestarAuthConfig
    from litestar_auth.db.base import BaseUserStore
    from litestar_auth.manager import BaseUserManager


_DEFAULT_USER_MANAGER_CONSTRUCTOR_DESCRIPTION = (
    "user_manager_class(user_db, *, password_helper=..., security=..., "
    "password_validator=..., backends=..., login_identifier=..., unsafe_testing=...)"
)
_DEFAULT_USER_MANAGER_ID_PARSER_FALLBACK_DESCRIPTION = (
    "When user_manager_security is unset, the default builder still passes "
    "security=UserManagerSecurity(...) with LitestarAuthConfig.id_parser folded into that bundle "
    "(not a standalone id_parser= kwarg)."
)
_DEFAULT_USER_MANAGER_FACTORY_GUIDANCE = (
    "Configure user_manager_factory for non-canonical or factory-owned manager construction."
)


def default_password_validator_factory[UP: UserProtocol[Any], ID](
    _config: LitestarAuthConfig[UP, ID],
) -> Callable[[str], None]:
    """Build the default plugin password validator.

    Returns:
        A validator enforcing the plugin's default password-length policy.
    """
    return partial(require_password_length, minimum_length=DEFAULT_MINIMUM_PASSWORD_LENGTH)


def _format_default_user_manager_managed_security_error(managed_security_keys: tuple[str, ...]) -> str:
    """Return the shared diagnostic for legacy plugin-managed security kwargs."""
    invalid_keys = ", ".join(managed_security_keys)
    return (
        "The default plugin user-manager builder only accepts verification/reset/TOTP "
        "secrets and id_parser through user_manager_security. "
        "user_manager_security is the canonical plugin-managed path for manager secrets and id_parser. "
        f"Remove these keys from user_manager_kwargs: {invalid_keys}. {_DEFAULT_USER_MANAGER_FACTORY_GUIDANCE}"
    )


@dataclass(frozen=True, slots=True)
class _DefaultUserManagerBuilderContract[UP: UserProtocol[Any], ID]:
    """Shared internal contract for plugin-owned default user-manager construction."""

    config: LitestarAuthConfig[UP, ID]
    password_helper: object
    password_validator: Callable[[str], None] | None
    backends: tuple[object, ...] = ()

    @property
    def effective_manager_kwargs(self) -> dict[str, Any]:
        """Return manager kwargs with the default password helper materialized."""
        effective_manager_kwargs = dict(self.config.user_manager_kwargs)
        if "password_helper" not in effective_manager_kwargs:
            effective_manager_kwargs["password_helper"] = self.password_helper
        return effective_manager_kwargs

    @property
    def manager_inputs(self) -> ManagerConstructorInputs[ID]:
        """Return the normalized constructor inputs for the default builder."""
        return ManagerConstructorInputs(
            manager_kwargs=self.effective_manager_kwargs,
            manager_security=self.config.user_manager_security,
            password_validator=self.password_validator,
            backends=self.backends,
            login_identifier=self.config.login_identifier,
            id_parser=self.config.id_parser,
        )

    def build_kwargs(self) -> dict[str, Any]:
        """Materialize the canonical default-builder kwargs for one call site.

        Returns:
            The concrete constructor kwargs for the requested default-builder surface.

        Raises:
            ConfigurationError: If plugin-managed secrets or ``id_parser`` are supplied
                through ``user_manager_kwargs`` instead of ``user_manager_security``.
        """
        manager_inputs = self.manager_inputs
        if manager_inputs.managed_security_keys:
            msg = _format_default_user_manager_managed_security_error(manager_inputs.managed_security_keys)
            raise ConfigurationError(msg)

        manager_kwargs = manager_inputs.build_kwargs()
        if "password_validator" not in self.effective_manager_kwargs:
            manager_kwargs["password_validator"] = self.password_validator
        if "unsafe_testing" not in manager_kwargs:
            manager_kwargs["unsafe_testing"] = self.config.unsafe_testing
        return manager_kwargs

    @staticmethod
    def build_constructor_mismatch_message(manager_name: str, exc: TypeError) -> str:
        """Return the shared constructor-mismatch diagnostic for the default builder."""
        return (
            f"{manager_name!r} (user_manager_class) is incompatible with the default plugin "
            "builder contract. Without user_manager_factory, the plugin calls "
            f"{_DEFAULT_USER_MANAGER_CONSTRUCTOR_DESCRIPTION}. "
            f"{_DEFAULT_USER_MANAGER_ID_PARSER_FALLBACK_DESCRIPTION} "
            f"{_DEFAULT_USER_MANAGER_FACTORY_GUIDANCE} Original error: {exc}"
        )


def _build_default_user_manager_contract[UP: UserProtocol[Any], ID](
    config: LitestarAuthConfig[UP, ID],
    *,
    password_helper: object,
    password_validator: Callable[[str], None] | None,
    backends: tuple[object, ...] = (),
) -> _DefaultUserManagerBuilderContract[UP, ID]:
    """Return the shared contract for plugin-owned default manager construction."""
    return _DefaultUserManagerBuilderContract(
        config=config,
        password_helper=password_helper,
        password_validator=password_validator,
        backends=backends,
    )


def _build_default_user_manager_kwargs[UP: UserProtocol[Any], ID](
    config: LitestarAuthConfig[UP, ID],
    *,
    backends: tuple[object, ...] = (),
) -> dict[str, Any]:
    """Materialize the exact kwargs used by the runtime default manager builder.

    Returns:
        The concrete constructor kwargs that :func:`build_user_manager` passes to
        ``user_manager_class(...)``.
    """
    return _build_default_user_manager_contract(
        config,
        password_helper=config.resolve_password_helper(),
        password_validator=resolve_password_validator(config),
        backends=backends,
    ).build_kwargs()


def _build_default_user_manager_validation_kwargs[UP: UserProtocol[Any], ID](
    config: LitestarAuthConfig[UP, ID],
    *,
    backends: tuple[object, ...] = (),
) -> dict[str, Any]:
    """Materialize constructor-shape kwargs without executing runtime validator factories.

    Validation only needs the keyword surface, not the runtime validator object. The
    default builder still reserves the ``password_validator`` slot when the caller did
    not explicitly own it through ``user_manager_kwargs``.

    Returns:
        Constructor kwargs matching the startup validation contract for the default
        user-manager builder.
    """
    return _build_default_user_manager_contract(
        config,
        password_helper=object(),
        password_validator=None,
        backends=backends,
    ).build_kwargs()


def build_user_manager[UP: UserProtocol[Any], ID](
    *,
    session: AsyncSession,
    user_db: BaseUserStore[UP, ID],
    config: LitestarAuthConfig[UP, ID],
    backends: tuple[object, ...] = (),
) -> BaseUserManager[UP, ID]:
    """Instantiate the configured user manager through the explicit factory contract.

    Args:
        session: Request-local SQLAlchemy session (unused by the default builder; kept
            for custom ``user_manager_factory`` symmetry with the plugin).
        user_db: User persistence adapter for this session.
        config: Plugin configuration.
        backends: Session-bound authentication backends (overrides any ``backends`` key
            in ``user_manager_kwargs``).

    Returns:
        A request-scoped user manager instance built from the plugin config. When
        ``user_manager_factory`` is omitted, the default builder always calls the
        canonical ``BaseUserManager``-style constructor surface, including the
        plugin-managed ``unsafe_testing`` flag, and expects ``user_manager_class`` to
        accept that contract. Custom constructors that narrow or rename that surface
        must be built through ``user_manager_factory``.

    """
    del session
    manager_kwargs = _build_default_user_manager_kwargs(config, backends=backends)
    return config.user_manager_class(user_db, **manager_kwargs)


def resolve_password_validator[UP: UserProtocol[Any], ID](
    config: LitestarAuthConfig[UP, ID],
) -> Callable[[str], None] | None:
    """Resolve the password validator requested by plugin configuration.

    Returns:
        The explicitly configured password validator when present, otherwise the
        plugin-owned default validator for the fixed default builder contract.
    """
    manager_inputs = ManagerConstructorInputs(manager_kwargs=config.user_manager_kwargs)
    explicit_validator = manager_inputs.explicit_password_validator
    if explicit_validator is not None:
        return explicit_validator
    if config.password_validator_factory is not None:
        return config.password_validator_factory(config)
    return default_password_validator_factory(config)


def resolve_user_manager_factory[UP: UserProtocol[Any], ID](
    config: LitestarAuthConfig[UP, ID],
) -> UserManagerFactory[UP, ID]:
    """Resolve the explicit builder used to create request-scoped user managers.

    Returns:
        The builder callable that the plugin should use for request-scoped managers.
    """
    if config.user_manager_factory is not None:
        return config.user_manager_factory
    return build_user_manager
