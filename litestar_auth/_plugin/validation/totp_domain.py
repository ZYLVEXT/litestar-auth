"""TOTP domain validation for plugin configuration."""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

from litestar_auth._plugin.features import TOTP_STEPUP_POLICY_ENDPOINTS
from litestar_auth._plugin.validation import totp as _totp_validation
from litestar_auth._plugin.validation._core import format_configuration_message
from litestar_auth._plugin.validation._predicates import user_model_defines_field
from litestar_auth.exceptions import ConfigurationError
from litestar_auth.types import UserProtocol

if TYPE_CHECKING:
    from litestar_auth._plugin.config import LitestarAuthConfig


def validate_totp_domain_config[UP: UserProtocol[Any], ID](config: LitestarAuthConfig[UP, ID]) -> None:
    """Validate TOTP feature-level configuration before deeper security checks."""
    validate_totp_user_model_protocol(config)
    validate_totp_stepup_policy_config(config)
    _totp_validation.validate_totp_config(config)


def validate_totp_user_model_protocol[UP: UserProtocol[Any], ID](config: LitestarAuthConfig[UP, ID]) -> None:
    """Ensure TOTP-enabled configs use a user model that exposes TOTP fields.

    Raises:
        ConfigurationError: If ``totp_config`` is set but ``user_model`` does not expose
            the fields required by ``TotpUserProtocol``.
    """
    if config.totp_config is None:
        return

    required_fields = ("email", "totp_secret")
    missing_fields = tuple(
        field_name for field_name in required_fields if not user_model_defines_field(config.user_model, field_name)
    )
    if not missing_fields:
        return

    user_model_name = getattr(config.user_model, "__name__", config.user_model)
    missing_fields_list = ", ".join(repr(field_name) for field_name in missing_fields)
    msg = (
        f"TOTP is configured but user_model {user_model_name!r} does not expose "
        f"fields required by TotpUserProtocol: {missing_fields_list}."
    )
    raise ConfigurationError(format_configuration_message(msg))


def validate_totp_stepup_policy_config[UP: UserProtocol[Any], ID](config: LitestarAuthConfig[UP, ID]) -> None:
    """Validate endpoint ids and modes for the TOTP step-up policy map.

    Raises:
        ConfigurationError: If an endpoint id or policy mode is not supported.
    """
    allowed_modes = {"required_when_enrolled", "always_required", "off"}
    for endpoint, mode in config.totp_stepup_policy.items():
        if endpoint not in TOTP_STEPUP_POLICY_ENDPOINTS:
            msg = f"Unknown totp_stepup_policy endpoint {endpoint!r}."
            raise ConfigurationError(format_configuration_message(msg))
        if mode not in allowed_modes:
            msg = f"Invalid totp_stepup_policy mode {mode!r} for endpoint {endpoint!r}."
            raise ConfigurationError(format_configuration_message(msg))
