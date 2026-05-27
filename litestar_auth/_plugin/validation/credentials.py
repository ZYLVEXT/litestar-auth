"""Credential and user-manager validation for plugin configuration."""

from __future__ import annotations

import inspect
from typing import TYPE_CHECKING, Any, cast

from litestar_auth._manager.construction import ManagerConstructorInputs
from litestar_auth._manager.security import validate_user_manager_security_secret_roles_are_distinct
from litestar_auth._plugin.validation._core import format_configuration_message
from litestar_auth._plugin.validation.login_identifier import validate_user_model_login_identifier_fields
from litestar_auth._plugin.validation.roles import (
    validate_role_capable_user_model_surfaces,
    validate_superuser_role_name_config,
)
from litestar_auth.config import MINIMUM_SECRET_LENGTH, validate_production_secret
from litestar_auth.exceptions import ConfigurationError
from litestar_auth.types import UserProtocol

if TYPE_CHECKING:
    from litestar_auth._plugin.config import LitestarAuthConfig
    from litestar_auth._plugin.session_binding import _AccountStateValidator as PluginAccountStateValidator


def validate_credential_config[UP: UserProtocol[Any], ID](config: LitestarAuthConfig[UP, ID]) -> None:
    """Validate credential and user-manager contracts needed during construction.

    Raises:
        ValueError: If user-listing support is requested without ``list_users()``.
    """
    validate_user_manager_security_config(config)
    validate_superuser_role_name_config(config)
    validate_password_validator_config(config)
    validate_default_user_manager_constructor_contract(config)
    validate_user_model_login_identifier_fields(config)
    validate_role_capable_user_model_surfaces(config)

    if config.include_users and not callable(getattr(config.user_manager_class, "list_users", None)):
        msg = "include_users=True requires user_manager_class to define list_users()."
        raise ValueError(msg)


def validate_user_manager_security_config[UP: UserProtocol[Any], ID](config: LitestarAuthConfig[UP, ID]) -> None:
    """Validate manager secret wiring and the supported production secret posture.

    Raises:
        ConfigurationError: If the typed contract conflicts with the top-level
            ``id_parser`` declaration.
    """
    manager_inputs = ManagerConstructorInputs(
        manager_security=config.user_manager_security,
        id_parser=config.id_parser,
    )
    manager_security = config.user_manager_security
    if manager_security is not None and (
        config.id_parser is not None
        and manager_security.id_parser is not None
        and config.id_parser is not manager_security.id_parser
    ):
        msg = (
            "Configure id_parser via user_manager_security.id_parser or LitestarAuthConfig.id_parser, "
            "not both with different values."
        )
        raise ConfigurationError(format_configuration_message(msg))

    if config.unsafe_testing:
        return

    effective_security = manager_inputs.effective_security
    if effective_security.login_identifier_telemetry_secret is not None:
        validate_production_secret(
            effective_security.login_identifier_telemetry_secret,
            label="login_identifier_telemetry_secret",
            unsafe_testing=config.unsafe_testing,
            minimum_length=MINIMUM_SECRET_LENGTH,
        )
    if config.totp_config is not None and effective_security.totp_recovery_code_lookup_secret is not None:
        validate_production_secret(
            effective_security.totp_recovery_code_lookup_secret,
            label="totp_recovery_code_lookup_secret",
            unsafe_testing=config.unsafe_testing,
            minimum_length=MINIMUM_SECRET_LENGTH,
        )
    validate_user_manager_security_secret_roles_are_distinct(
        effective_security,
        totp_pending_secret=config.totp_config.totp_pending_secret if config.totp_config is not None else None,
        oauth_flow_cookie_secret=(
            config.oauth_config.oauth_flow_cookie_secret if config.oauth_config is not None else None
        ),
    )


def validate_password_validator_config[UP: UserProtocol[Any], ID](_config: LitestarAuthConfig[UP, ID]) -> None:
    """Validate password-validator wiring for the configured user-manager builder."""


def validate_default_user_manager_constructor_contract[UP: UserProtocol[Any], ID](
    config: LitestarAuthConfig[UP, ID],
) -> None:
    """Fail fast when ``user_manager_class`` is incompatible with the default builder.

    Raises:
        ConfigurationError: If ``user_manager_factory`` is unset and the configured
            ``user_manager_class`` does not accept the default builder contract.
    """
    if config.user_manager_factory is not None:
        return

    from litestar_auth._plugin.user_manager_builder import (  # noqa: PLC0415
        _DEFAULT_USER_MANAGER_FACTORY_GUIDANCE,
        _build_default_user_manager_contract,
        _build_default_user_manager_validation_kwargs,
    )

    manager_class = config.user_manager_class
    if manager_class is None:
        msg = (
            "user_manager_class must be configured when user_manager_factory is unset. "
            f"{_DEFAULT_USER_MANAGER_FACTORY_GUIDANCE}"
        )
        raise ConfigurationError(format_configuration_message(msg))
    manager_name = getattr(manager_class, "__name__", repr(manager_class))
    contract = _build_default_user_manager_contract(
        config,
        password_helper=config.resolve_password_helper(),
        password_validator=None,
    )
    try:
        constructor_signature = inspect.signature(manager_class)
    except (TypeError, ValueError) as exc:
        msg = (
            f"{manager_name!r} (user_manager_class) must expose an introspectable constructor when "
            f"user_manager_factory is unset. {_DEFAULT_USER_MANAGER_FACTORY_GUIDANCE}"
        )
        raise ConfigurationError(format_configuration_message(msg)) from exc

    try:
        constructor_signature.bind(
            object(),
            **_build_default_user_manager_validation_kwargs(config),
        )
    except TypeError as exc:
        msg = contract.build_constructor_mismatch_message(manager_name, exc)
        raise ConfigurationError(format_configuration_message(msg)) from exc


def resolve_user_manager_account_state_validator[UP: UserProtocol[Any]](
    user_manager_class: type[object] | None,
) -> PluginAccountStateValidator[UP]:
    """Resolve the plugin-managed manager-class account-state validator contract.

    Returns:
        The callable ``require_account_state(user, *, require_verified=False)``
        exposed by ``user_manager_class``.

    Raises:
        TypeError: If ``user_manager_class`` does not expose a callable
            ``require_account_state()``.
    """
    validator = getattr(user_manager_class, "require_account_state", None)
    if callable(validator):
        return cast("PluginAccountStateValidator[UP]", validator)

    manager_name = getattr(user_manager_class, "__name__", repr(user_manager_class))
    msg = (
        f"{manager_name!r} (user_manager_class) must expose "
        "require_account_state(user, *, require_verified=False). "
        "Subclass litestar_auth.manager.BaseUserManager for the default implementation, "
        "or define require_account_state on your manager class with the same contract."
    )
    raise TypeError(msg)
