"""Central configuration helpers for litestar-auth.

This module contains small, shared primitives used across the library to keep
security-relevant validation consistent, including secret-length checks and
explicit unsafe-testing overrides.
"""

from __future__ import annotations

import math
import secrets
import warnings
from collections import Counter
from dataclasses import dataclass
from re import fullmatch
from typing import Final

from litestar_auth._secret_roles import (
    JWT_ACCESS_TOKEN_AUDIENCE,
    RESET_PASSWORD_TOKEN_AUDIENCE,
    TOTP_ENROLL_AUDIENCE,
    TOTP_PENDING_AUDIENCE,
    VERIFY_TOKEN_AUDIENCE,
    SecretRoleValues,
    validate_secret_roles_are_distinct,
)
from litestar_auth.exceptions import ConfigurationError

MINIMUM_SECRET_LENGTH = 32
# Entropy floor recommended for production-config secrets. 128 bits rejects
# degenerate misconfig and short repeated structured patterns while comfortably
# accepting ``secrets.token_hex(32)`` and ``secrets.token_urlsafe(32)``.
# Operators can pass a stricter floor through :func:`validate_secret_strength`.
MINIMUM_SECRET_ENTROPY_BITS = 128.0
_REPEATED_SECRET_UNIT_LENGTH_FLOOR = MINIMUM_SECRET_LENGTH // 2
# Shared password-length bounds for built-in validation and schema metadata.
DEFAULT_MINIMUM_PASSWORD_LENGTH = 12
MAX_PASSWORD_LENGTH = 128
# Small validation margin for JWT time claims (`exp` / `nbf`) to absorb normal clock skew.
JWT_TIME_CLAIM_LEEWAY_SECONDS = 30
OAUTH_PROVIDER_NAME_PATTERN = r"[A-Za-z0-9](?:[A-Za-z0-9_-]{0,62}[A-Za-z0-9])?"

__all__ = (
    "DEFAULT_MINIMUM_PASSWORD_LENGTH",
    "JWT_ACCESS_TOKEN_AUDIENCE",
    "JWT_TIME_CLAIM_LEEWAY_SECONDS",
    "MAX_PASSWORD_LENGTH",
    "MINIMUM_SECRET_ENTROPY_BITS",
    "MINIMUM_SECRET_LENGTH",
    "OAUTH_PROVIDER_NAME_PATTERN",
    "RESET_PASSWORD_TOKEN_AUDIENCE",
    "TOTP_ENROLL_AUDIENCE",
    "TOTP_PENDING_AUDIENCE",
    "UNSET",
    "VERIFY_TOKEN_AUDIENCE",
    "OAuthProviderConfig",
    "SecretRoleValues",
    "UnsetType",
    "require_password_length",
    "resolve_trusted_proxy_hops",
    "resolve_trusted_proxy_setting",
    "validate_oauth_provider_name",
    "validate_production_secret",
    "validate_secret_length",
    "validate_secret_roles_are_distinct",
    "validate_secret_strength",
)


@dataclass(frozen=True, slots=True)
class UnsetType:
    """Typed marker for omitted config values that need default resolution."""

    def __bool__(self) -> bool:
        """Treat the sentinel as false in legacy truth-value checks.

        Returns:
            Always ``False``.
        """
        return False


UNSET: Final = UnsetType()


def validate_oauth_provider_name(name: str, *, label: str = "OAuth provider name") -> str:
    """Validate and return a route/cookie/callback-safe OAuth provider name.

    Returns:
        The validated provider name.

    Raises:
        ConfigurationError: If ``name`` is empty or contains path, cookie, or
            callback-URL unsafe characters.
    """
    if fullmatch(OAUTH_PROVIDER_NAME_PATTERN, name):
        return name

    msg = (
        f"{label} must match {OAUTH_PROVIDER_NAME_PATTERN!r}: use 1-64 ASCII letters, "
        "digits, underscores, or hyphens, and start/end with an alphanumeric character."
    )
    raise ConfigurationError(msg)


@dataclass(frozen=True, slots=True)
class OAuthProviderConfig:
    """One entry in :attr:`~litestar_auth._plugin.config.OAuthConfig.oauth_providers`.

    Plugin-owned OAuth routes use ``name`` as the ``{provider}`` segment (for example
    ``GET {auth_path}/oauth/{name}/callback``). ``client`` must be an httpx-oauth-compatible
    OAuth2 client instance (typically :class:`httpx_oauth.oauth2.BaseOAuth2`).

    The ``client`` field is typed as :class:`object` so core modules do not require a hard
    dependency on httpx-oauth at import time.

    Attributes:
        name: Logical provider name used in URLs and ``oauth_provider_scopes`` keys.
        client: OAuth2 client instance passed through to the OAuth service layer.
    """

    name: str
    client: object

    def __post_init__(self) -> None:
        """Validate provider names before they are used in routes, cookies, and callback URLs."""
        validate_oauth_provider_name(self.name)

    @classmethod
    def coerce(cls, value: object) -> OAuthProviderConfig:
        """Return ``value`` when it is already an :class:`OAuthProviderConfig`.

        Raises:
            TypeError: If ``value`` is not an :class:`OAuthProviderConfig`.
        """
        if isinstance(value, cls):
            return value
        msg = "OAuth provider entries must be OAuthProviderConfig(name=..., client=...)."
        raise TypeError(msg)


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


def _shannon_entropy_bits(value: str) -> float:
    """Return an approximate Shannon entropy estimate for ``value`` in bits.

    Uses observed per-character frequencies, so highly repetitive or
    low-alphabet strings (e.g. ``"a" * 32``) collapse to near-zero bits while
    uniformly drawn random tokens approach the maximum implied by the
    alphabet (e.g. ``secrets.token_hex(32)`` reports ≈252 bits over its
    16-symbol alphabet across 64 characters).

    This is a coarse upper-bound estimator, not a security guarantee:
    structured but high-alphabet inputs (English passphrases, base64-encoded
    timestamps) can score well above the configured floor.
    """
    if not value:
        return 0.0
    counter = Counter(value)
    length = len(value)
    return -sum((count / length) * math.log2(count / length) for count in counter.values()) * length


def _shortest_repeating_unit(value: str) -> str:
    """Return the smallest substring that exactly reconstructs a repeated value."""
    length = len(value)
    for unit_length in range(1, (length // 2) + 1):
        if length % unit_length != 0:
            continue
        unit = value[:unit_length]
        if unit * (length // unit_length) == value:
            return unit
    return value


def _estimated_secret_entropy_bits(value: str) -> float:
    """Estimate secret entropy with a cap for exactly repeated structured patterns.

    Observed Shannon entropy treats ``"abc123" * 22`` as a 132-character
    six-symbol distribution, even though the configured material is just one
    short phrase copied repeatedly. When a secret is an exact periodic string
    built from a short unit, cap its score at the entropy of that unit;
    otherwise retain the observed-frequency estimate used by older releases.

    Returns:
        Estimated entropy bits used for production secret validation.
    """
    repeating_unit = _shortest_repeating_unit(value)
    if repeating_unit == value or len(repeating_unit) >= _REPEATED_SECRET_UNIT_LENGTH_FLOOR:
        return _shannon_entropy_bits(value)
    return _shannon_entropy_bits(repeating_unit)


def validate_secret_strength(
    secret: str,
    *,
    label: str,
    minimum_length: int = MINIMUM_SECRET_LENGTH,
    minimum_entropy_bits: float = MINIMUM_SECRET_ENTROPY_BITS,
) -> None:
    """Validate that a configured secret clears length and entropy floors.

    The base library checks length only at constructor seams to keep test
    fixtures interchangeable with production config. ``validate_secret_strength``
    is the recommended operator-side gate for production deployments: wire it
    into the application's startup hook (or a custom `LitestarAuthConfig`
    bootstrap path) to fail closed on degenerate inputs like ``"a" * 32``,
    keyboard-mashed strings, or other low-entropy material that the chars-count
    check alone cannot reject.

    Args:
        secret: Secret value to validate.
        label: Human-readable label used in error messages.
        minimum_length: Minimum length in characters (defaults to
            :data:`MINIMUM_SECRET_LENGTH`).
        minimum_entropy_bits: Minimum approximate entropy in bits
            (defaults to :data:`MINIMUM_SECRET_ENTROPY_BITS`). Pass ``0`` to
            skip the entropy check while keeping length validation.

    Raises:
        ConfigurationError: When ``secret`` fails either the length floor or
            the entropy floor. The same exception type is used as
            :func:`validate_secret_length` so existing operator handlers stay
            compatible.
    """
    validate_secret_length(secret, label=label, minimum_length=minimum_length)
    if minimum_entropy_bits <= 0:
        return
    bits = _estimated_secret_entropy_bits(secret)
    if bits < minimum_entropy_bits:
        msg = (
            f"{label} has insufficient entropy (~{bits:.0f} bits; required "
            f"{minimum_entropy_bits:.0f}). Generate via "
            'python -c "import secrets; print(secrets.token_hex(32))".'
        )
        raise ConfigurationError(msg)


def validate_production_secret(
    secret: str,
    *,
    label: str,
    unsafe_testing: bool = False,
    minimum_length: int = MINIMUM_SECRET_LENGTH,
    minimum_entropy_bits: float = MINIMUM_SECRET_ENTROPY_BITS,
) -> None:
    """Validate production secret material, preserving explicit test shortcuts.

    Production token, HMAC, and encryption secrets need both a length floor and
    a basic entropy floor. Repeated-character strings such as ``"a" * 32`` pass
    length-only validation but are not safe signing or encryption material.
    ``unsafe_testing=True`` keeps fixture-only shortcuts possible while making
    the weaker posture explicit at the call site.
    """
    if unsafe_testing:
        return
    validate_secret_strength(
        secret,
        label=label,
        minimum_length=minimum_length,
        minimum_entropy_bits=minimum_entropy_bits,
    )


def require_password_length(
    password: str,
    minimum_length: int = DEFAULT_MINIMUM_PASSWORD_LENGTH,
    *,
    maximum_length: int = MAX_PASSWORD_LENGTH,
) -> None:
    """Raise when a password falls outside the configured length bounds.

    The default ``minimum_length`` matches the password-length metadata exposed
    for app-owned user schemas via ``litestar_auth.schemas.UserPasswordField``.

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
    unsafe_testing: bool = False,
) -> str:
    """Resolve a configured token secret or an explicit unsafe-testing fallback.

    Args:
        secret: Configured token secret, if any.
        label: Human-readable label used in warnings and exceptions.
        warning_stacklevel: Stacklevel used for unsafe-testing warnings.
        unsafe_testing: When ``True``, allow generated temporary secrets and skip
            production minimum-length enforcement.

    Returns:
        The configured token secret, or a cryptographically random hex string when
        ``unsafe_testing=True`` and no secret was provided.

    Raises:
        ConfigurationError: If the secret is missing outside explicit
            ``unsafe_testing`` mode or too short outside that mode.
    """
    if secret is None:
        if unsafe_testing:
            warnings.warn(
                f"{label} not provided; using a randomly generated secret because "
                "unsafe_testing=True. Set an explicit secret for production.",
                UserWarning,
                stacklevel=warning_stacklevel,
            )
            return secrets.token_hex(32)

        msg = (
            f"{label} not provided. Set an explicit secret in production, e.g. "
            'python -c "import secrets; print(secrets.token_hex(32))"'
        )
        raise ConfigurationError(msg)

    validate_production_secret(secret, label=label, unsafe_testing=unsafe_testing)

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


def resolve_trusted_proxy_hops(*, trusted_proxy_hops: object) -> int:
    """Validate and normalize trusted-proxy hop counts.

    Args:
        trusted_proxy_hops: Candidate X-Forwarded-For hop count from configuration.

    Returns:
        Positive integer hop count.

    Raises:
        ConfigurationError: If ``trusted_proxy_hops`` is not a positive integer.
    """
    if isinstance(trusted_proxy_hops, int) and not isinstance(trusted_proxy_hops, bool) and trusted_proxy_hops > 0:
        return trusted_proxy_hops

    msg = "trusted_proxy_hops must be a positive integer."
    raise ConfigurationError(msg)
