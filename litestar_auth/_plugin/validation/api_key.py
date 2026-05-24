"""API-key plugin configuration validation."""

from __future__ import annotations

import re
from typing import TYPE_CHECKING, Any

from litestar_auth._plugin.validation._core import (
    IssueCollector,
    format_configuration_message,
    format_validation_issues,
)
from litestar_auth.config import (
    MINIMUM_SECRET_LENGTH,
    SecretRoleValues,
    validate_production_secret,
    validate_secret_roles_are_distinct,
)
from litestar_auth.exceptions import ConfigurationError
from litestar_auth.types import UserProtocol

if TYPE_CHECKING:
    from litestar_auth._plugin.config import LitestarAuthConfig
    from litestar_auth._plugin.features import ApiKeyConfig


def validate_api_key_config[UP: UserProtocol[Any], ID](config: LitestarAuthConfig[UP, ID]) -> None:
    """Validate API-key feature configuration before backend registration."""
    api_key_config = config.api_keys
    if not api_key_config.enabled:
        return

    _validate_api_key_secret(config)
    _validate_api_key_policy_fields(api_key_config)
    _validate_api_key_signing_config(config)
    _validate_api_key_format_fields(api_key_config)
    _validate_api_key_signing_secret_distinctness(config)


def _validate_api_key_secret[UP: UserProtocol[Any], ID](config: LitestarAuthConfig[UP, ID]) -> None:
    """Validate API-key hash-secret presence and production posture.

    Raises:
        ConfigurationError: If the API-key hash secret is missing or unsafe.
    """
    if config.user_manager_security is None or not config.user_manager_security.api_key_hash_secret:
        msg = "api_key_hash_secret is required on user_manager_security when api_keys.enabled is True."
        raise ConfigurationError(
            format_configuration_message(msg, field="user_manager_security.api_key_hash_secret"),
        )
    validate_production_secret(
        config.user_manager_security.api_key_hash_secret,
        label="api_key_hash_secret",
        unsafe_testing=config.unsafe_testing,
        minimum_length=MINIMUM_SECRET_LENGTH,
    )


def _validate_api_key_policy_fields(api_key_config: ApiKeyConfig) -> None:
    """Validate API-key policy scalar fields.

    Raises:
        ConfigurationError: If a scalar policy value is outside its accepted range.
    """
    collector = IssueCollector()
    if api_key_config.max_keys_per_user <= 0:
        collector.add("api_keys.max_keys_per_user must be greater than 0.", field="api_keys.max_keys_per_user")
    if api_key_config.scope_subset_check and not api_key_config.allowed_scopes:
        collector.add(
            "api_keys.allowed_scopes must be non-empty when scope_subset_check is True.",
            field="api_keys.allowed_scopes",
        )
    if api_key_config.last_used_throttle_seconds < 0:
        collector.add(
            "api_keys.last_used_throttle_seconds must be non-negative.",
            field="api_keys.last_used_throttle_seconds",
        )
    if api_key_config.last_used_write_strategy not in {"disabled", "immediate", "throttled"}:
        collector.add(
            "api_keys.last_used_write_strategy must be 'disabled', 'immediate', or 'throttled'.",
            field="api_keys.last_used_write_strategy",
        )
    if api_key_config.signing_skew_seconds < 1:
        collector.add("api_keys.signing_skew_seconds must be greater than 0.", field="api_keys.signing_skew_seconds")
    if api_key_config.signed_body_max_bytes < 1:
        collector.add("api_keys.signed_body_max_bytes must be greater than 0.", field="api_keys.signed_body_max_bytes")
    if api_key_config.signed_body_max_messages < 1:
        collector.add(
            "api_keys.signed_body_max_messages must be greater than 0.",
            field="api_keys.signed_body_max_messages",
        )
    if collector.issues:
        raise ConfigurationError(format_validation_issues(collector.issues))


def _validate_api_key_signing_config[UP: UserProtocol[Any], ID](config: LitestarAuthConfig[UP, ID]) -> None:
    """Validate API-key request-signing prerequisites.

    Raises:
        ConfigurationError: If request signing lacks required storage or crypto configuration.
    """
    api_key_config = config.api_keys
    if api_key_config.signing_enabled and api_key_config.secret_encryption_keyring is None:
        msg = "api_keys.secret_encryption_keyring is required when api_keys.signing_enabled is True."
        raise ConfigurationError(format_configuration_message(msg, field="api_keys.secret_encryption_keyring"))
    if api_key_config.signing_enabled and api_key_config.nonce_store is None and not config.unsafe_testing:
        msg = "api_keys.nonce_store is required when api_keys.signing_enabled is True."
        raise ConfigurationError(format_configuration_message(msg, field="api_keys.nonce_store"))
    _validate_api_key_signing_nonce_store(config)


def _validate_api_key_signing_nonce_store[UP: UserProtocol[Any], ID](config: LitestarAuthConfig[UP, ID]) -> None:
    """Validate request-signing nonce storage for multi-worker deployments.

    Raises:
        ConfigurationError: If a multi-worker deployment uses a process-local nonce store.
    """
    api_key_config = config.api_keys
    if not api_key_config.signing_enabled:
        return
    if not config.deployment_worker_count or config.deployment_worker_count <= 1:
        return
    nonce_store = api_key_config.nonce_store
    if nonce_store is None or bool(getattr(nonce_store, "is_shared_across_workers", False)):
        return
    msg = (
        "API-key request signing nonce_store must be shared across workers when "
        "deployment_worker_count is greater than 1. Use RedisApiKeyNonceStore."
    )
    raise ConfigurationError(format_configuration_message(msg, field="api_keys.nonce_store"))


def _validate_api_key_format_fields(api_key_config: ApiKeyConfig) -> None:
    """Validate API-key prefix and environment marker formatting.

    Raises:
        ConfigurationError: If prefix or environment marker values have invalid formats.
    """
    if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9-]{0,31}", api_key_config.environment_marker):
        msg = "api_keys.environment_marker must be 1-32 ASCII letters, digits, or hyphens."
        raise ConfigurationError(format_configuration_message(msg, field="api_keys.environment_marker"))
    if not re.fullmatch(r"[A-Za-z][A-Za-z0-9-]{0,15}", api_key_config.prefix):
        msg = "api_keys.prefix must be 1-16 ASCII letters, digits, or hyphens and start with a letter."
        raise ConfigurationError(format_configuration_message(msg, field="api_keys.prefix"))


def _validate_api_key_signing_secret_distinctness[UP: UserProtocol[Any], ID](
    config: LitestarAuthConfig[UP, ID],
) -> None:
    """Validate that API-key signing encryption keys do not reuse other secret roles."""
    keyring = config.api_keys.secret_encryption_keyring
    security = config.user_manager_security
    if keyring is None or security is None or config.unsafe_testing:
        return
    for key in keyring.keys.values():
        secret = key.decode("utf-8") if isinstance(key, bytes) else key
        validate_secret_roles_are_distinct(
            SecretRoleValues(
                verification_token_secret=security.verification_token_secret,
                reset_password_token_secret=security.reset_password_token_secret,
                login_identifier_telemetry_secret=security.login_identifier_telemetry_secret,
                totp_secret_key=security.totp_secret_key,
                totp_pending_secret=None if config.totp_config is None else config.totp_config.totp_pending_secret,
                totp_recovery_code_lookup_secret=security.totp_recovery_code_lookup_secret,
                oauth_flow_cookie_secret=None
                if config.oauth_config is None
                else config.oauth_config.oauth_flow_cookie_secret,
                api_key_hash_secret=security.api_key_hash_secret,
                api_key_secret_encryption_key=secret,
            ),
        )
