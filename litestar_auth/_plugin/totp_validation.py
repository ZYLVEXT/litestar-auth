"""TOTP validation helpers for plugin configuration."""

from __future__ import annotations

import warnings
from typing import TYPE_CHECKING, Any

from litestar_auth._manager.construction import ManagerConstructorInputs
from litestar_auth._plugin.config import (
    _resolve_plugin_managed_totp_secret_storage_policy,
)
from litestar_auth._plugin.middleware import get_cookie_transports
from litestar_auth.config import MINIMUM_SECRET_LENGTH, validate_secret_length
from litestar_auth.exceptions import ConfigurationError
from litestar_auth.totp import SecurityWarning

if TYPE_CHECKING:
    from litestar_auth._plugin.config import LitestarAuthConfig, TotpConfig
    from litestar_auth.types import UserProtocol

_SUPPORTED_TOTP_ALGORITHMS = ("SHA256", "SHA512")


def validate_totp_secret_config[UP: UserProtocol[Any], ID](config: LitestarAuthConfig[UP, ID]) -> None:
    """Validate TOTP secret-material and algorithm requirements."""
    _validate_totp_pending_secret_config(config)


def validate_totp_encryption_config[UP: UserProtocol[Any], ID](config: LitestarAuthConfig[UP, ID]) -> None:
    """Validate production encryption requirements for persisted TOTP secrets."""
    _validate_totp_encryption_key(config)


def _validate_totp_pending_secret_config[UP: UserProtocol[Any], ID](config: LitestarAuthConfig[UP, ID]) -> None:
    """Validate TOTP pending-secret and algorithm constraints.

    Raises:
        ConfigurationError: If recovery-code lookup secret requirements are not satisfied.
        ValueError: If TOTP algorithm requirements are not satisfied.
    """
    if config.totp_config is None:
        return
    totp_config = config.totp_config

    validate_secret_length(
        totp_config.totp_pending_secret,
        label="totp_pending_secret",
        minimum_length=MINIMUM_SECRET_LENGTH,
    )
    if not getattr(totp_config, "totp_algorithm", None):
        msg = "totp_algorithm must be configured when totp_config is set."
        raise ValueError(msg)
    if totp_config.totp_algorithm not in _SUPPORTED_TOTP_ALGORITHMS:
        msg = "totp_algorithm must be one of: SHA256, SHA512."
        raise ValueError(msg)
    manager_inputs = ManagerConstructorInputs(
        manager_security=config.user_manager_security,
        id_parser=config.id_parser,
    )
    lookup_secret = manager_inputs.effective_security.totp_recovery_code_lookup_secret
    if not lookup_secret:
        msg = "totp_recovery_code_lookup_secret is required when totp_config is set."
        raise ConfigurationError(msg)
    if not config.unsafe_testing:
        validate_secret_length(
            lookup_secret,
            label="totp_recovery_code_lookup_secret",
            minimum_length=MINIMUM_SECRET_LENGTH,
        )


def _validate_totp_encryption_key[UP: UserProtocol[Any], ID](config: LitestarAuthConfig[UP, ID]) -> None:
    """Require TOTP secret encryption key in production when TOTP is enabled.

    Raises:
        ConfigurationError: If TOTP is configured but both ``totp_secret_keyring``
            and ``totp_secret_key`` are missing while ``config.unsafe_testing`` is false.
    """
    if config.totp_config is None or config.unsafe_testing:
        return
    notice = _resolve_plugin_managed_totp_secret_storage_policy(config)
    if notice is None or not notice.requires_explicit_production_opt_in:
        return

    msg = notice.production_validation_error
    if msg is None:  # pragma: no cover - missing-key posture always provides a validation error
        return
    raise ConfigurationError(msg)


def validate_totp_config[UP: UserProtocol[Any], ID](config: LitestarAuthConfig[UP, ID]) -> None:
    """Validate TOTP-specific configuration knobs."""
    if config.totp_config is None:
        return
    validate_totp_sub_config(
        config.totp_config,
        user_manager_class=config.user_manager_class,
        unsafe_testing=config.unsafe_testing,
    )
    if not config.unsafe_testing:
        cookie_transports = get_cookie_transports(config.resolve_startup_backends())
        if cookie_transports and not all(t.secure for t in cookie_transports):
            warnings.warn(
                "TOTP is enabled but CookieTransport.secure=False; TOTP secrets returned by "
                "/2fa/enable may be transmitted over unencrypted connections.",
                SecurityWarning,
                stacklevel=2,
            )


def _validate_totp_store_requirements(totp_config: TotpConfig, *, unsafe_testing: bool) -> None:
    """Validate production-only TOTP store requirements.

    Raises:
        ValueError: If a required TOTP store is missing outside unsafe testing.
    """
    pending_jti_store = getattr(totp_config, "totp_pending_jti_store", None)
    if pending_jti_store is None and not unsafe_testing:
        msg = "totp_pending_jti_store is required unless unsafe_testing=True."
        raise ValueError(msg)

    enrollment_store = getattr(totp_config, "totp_enrollment_store", None)
    if enrollment_store is None and not unsafe_testing:
        msg = "totp_enrollment_store is required unless unsafe_testing=True."
        raise ValueError(msg)

    require_replay_protection = bool(getattr(totp_config, "totp_require_replay_protection", False))
    used_tokens_store = getattr(totp_config, "totp_used_tokens_store", None)
    if require_replay_protection and used_tokens_store is None and not unsafe_testing:
        msg = "totp_require_replay_protection=True requires totp_used_tokens_store to be configured."
        raise ValueError(msg)


def _validate_totp_authenticate_requirement(
    totp_config: TotpConfig,
    *,
    user_manager_class: type[object] | None,
) -> None:
    """Validate password-gated TOTP enrollment manager support.

    Raises:
        ValueError: If password-gated TOTP enrollment lacks an authenticate hook.
    """
    if not totp_config.totp_enable_requires_password or callable(getattr(user_manager_class, "authenticate", None)):
        return

    msg = (
        "TOTP step-up enrollment is enabled by default. "
        "Configure user_manager_class.authenticate(identifier, password) or set "
        "totp_enable_requires_password=False explicitly (not recommended)."
    )
    raise ValueError(msg)


def validate_totp_sub_config(
    totp_config: TotpConfig,
    *,
    user_manager_class: type[object] | None,
    unsafe_testing: bool = False,
) -> None:
    """Validate a concrete ``TotpConfig`` payload.

    Raises:
        ValueError: If required TOTP configuration is missing or incompatible.
    """
    if not totp_config.totp_pending_secret:
        msg = "totp_config requires totp_pending_secret."
        raise ValueError(msg)
    _validate_totp_store_requirements(totp_config, unsafe_testing=unsafe_testing)
    _validate_totp_authenticate_requirement(totp_config, user_manager_class=user_manager_class)
