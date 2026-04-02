"""Central configuration helpers for litestar-auth.

This module contains small, shared primitives used across the library to keep
security-relevant validation consistent (e.g. secret length requirements and
testing-mode toggles).
"""

from __future__ import annotations

import os
import secrets
import warnings

from litestar_auth.exceptions import ConfigurationError

MINIMUM_SECRET_LENGTH = 32
# Shared password-length bounds for built-in validation and schema metadata.
DEFAULT_MINIMUM_PASSWORD_LENGTH = 12
MAX_PASSWORD_LENGTH = 128
# Canonical JWT audiences shared across account, auth, and TOTP flows.
VERIFY_TOKEN_AUDIENCE = "litestar-auth:verify"  # noqa: S105
RESET_PASSWORD_TOKEN_AUDIENCE = "litestar-auth:reset-password"  # noqa: S105
JWT_ACCESS_TOKEN_AUDIENCE = "litestar-auth:access"  # noqa: S105
TOTP_PENDING_AUDIENCE = "litestar-auth:2fa-pending"
TOTP_ENROLL_AUDIENCE = "litestar-auth:2fa-enroll"
type OAuthProviderConfig = tuple[str, object]


def is_testing() -> bool:
    """Return whether litestar-auth is running in testing mode."""
    return os.getenv("LITESTAR_AUTH_TESTING", "0") == "1"


def is_pytest_runtime() -> bool:
    """Return whether current process is executing under pytest."""
    return os.getenv("PYTEST_CURRENT_TEST") is not None


def validate_testing_mode_for_startup() -> None:
    """Fail fast when testing mode is enabled outside pytest runtimes.

    Raises:
        ConfigurationError: When ``LITESTAR_AUTH_TESTING=1`` is active in a non-test runtime.
    """
    if not is_testing() or is_pytest_runtime():
        return

    msg = (
        "LITESTAR_AUTH_TESTING=1 is intended for automated tests only and cannot be enabled "
        "for non-test runtime startup."
    )
    raise ConfigurationError(msg)


def validate_secret_length(secret: str, *, label: str, minimum_length: int = MINIMUM_SECRET_LENGTH) -> None:
    """Validate the configured secret length.

    Args:
        secret: Secret value to validate.
        label: Human-readable label used in error messages.
        minimum_length: Minimum length in characters.

    Raises:
        ConfigurationError: When ``secret`` is shorter than ``minimum_length``.
    """
    if len(secret) >= minimum_length:
        return

    msg = f"{label} must be at least {minimum_length} characters."
    raise ConfigurationError(msg)


def require_password_length(
    password: str,
    minimum_length: int = DEFAULT_MINIMUM_PASSWORD_LENGTH,
    *,
    maximum_length: int = MAX_PASSWORD_LENGTH,
) -> None:
    """Raise when a password falls outside the configured length bounds.

    The default ``minimum_length`` matches ``LitestarAuth``'s built-in password
    policy.

    Raises:
        ValueError: If ``password`` exceeds ``maximum_length`` or is shorter
            than ``minimum_length``.
    """
    if len(password) > maximum_length:
        msg = f"Password must be at most {maximum_length} characters long."
        raise ValueError(msg)

    if len(password) < minimum_length:
        msg = f"Password must be at least {minimum_length} characters long."
        raise ValueError(msg)


def _resolve_token_secret(
    secret: str | None,
    *,
    label: str,
    warning_stacklevel: int = 2,
) -> str:
    """Resolve a configured token secret or a testing-only generated secret.

    Args:
        secret: Configured token secret, if any.
        label: Human-readable label used in warnings and exceptions.
        warning_stacklevel: Stacklevel used for testing-mode warnings.

    Returns:
        The configured token secret, or a cryptographically random hex string when
        testing mode is enabled and no secret was provided.

    Raises:
        ConfigurationError: If the secret is missing outside testing mode or too short outside testing mode.
    """
    if secret is None:
        if is_testing():
            warnings.warn(
                f"{label} not provided; using a randomly generated secret because "
                "LITESTAR_AUTH_TESTING=1 is set. Set an explicit secret in production.",
                UserWarning,
                stacklevel=warning_stacklevel,
            )
            return secrets.token_hex(32)

        msg = (
            f"{label} not provided. Set an explicit secret in production, e.g. "
            'python -c "import secrets; print(secrets.token_hex(32))"'
        )
        raise ConfigurationError(msg)

    if not is_testing():
        validate_secret_length(secret, label=label)

    return secret


def resolve_trusted_proxy_setting(*, trusted_proxy: object) -> bool:
    """Validate and normalize trusted-proxy configuration flags.

    Args:
        trusted_proxy: Candidate trusted-proxy value from configuration.

    Returns:
        Normalized trusted-proxy boolean.

    Raises:
        ConfigurationError: If ``trusted_proxy`` is not a boolean value.
    """
    if isinstance(trusted_proxy, bool):
        return trusted_proxy

    msg = "trusted_proxy must be a boolean."
    raise ConfigurationError(msg)
