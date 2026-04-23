"""Central configuration helpers for litestar-auth.

This module contains small, shared primitives used across the library to keep
security-relevant validation consistent, including secret-length checks and
explicit unsafe-testing overrides.
"""

from __future__ import annotations

import secrets
import warnings
from dataclasses import dataclass
from re import fullmatch

from litestar_auth.exceptions import ConfigurationError

MINIMUM_SECRET_LENGTH = 32
# Shared password-length bounds for built-in validation and schema metadata.
DEFAULT_MINIMUM_PASSWORD_LENGTH = 12
MAX_PASSWORD_LENGTH = 128
# Small validation margin for JWT time claims (`exp` / `nbf`) to absorb normal clock skew.
JWT_TIME_CLAIM_LEEWAY_SECONDS = 30
# Canonical JWT audiences shared across account, auth, and TOTP flows.
VERIFY_TOKEN_AUDIENCE = "litestar-auth:verify"
RESET_PASSWORD_TOKEN_AUDIENCE = "litestar-auth:reset-password"
JWT_ACCESS_TOKEN_AUDIENCE = "litestar-auth:access"
TOTP_PENDING_AUDIENCE = "litestar-auth:2fa-pending"
TOTP_ENROLL_AUDIENCE = "litestar-auth:2fa-enroll"
OAUTH_PROVIDER_NAME_PATTERN = r"[A-Za-z0-9](?:[A-Za-z0-9_-]{0,62}[A-Za-z0-9])?"


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


@dataclass(frozen=True, slots=True)
class _SecretRole:
    """Describe one configured secret-bearing role and the flow it protects."""

    setting_name: str
    protected_surface: str
    audiences: tuple[str, ...] = ()

    def render_usage(self) -> str:
        """Return one human-readable description for errors and docs."""
        if self.audiences:
            audience_list = ", ".join(self.audiences)
            return f"{self.setting_name} ({self.protected_surface}; audiences: {audience_list})"
        return f"{self.setting_name} ({self.protected_surface}; no JWT audience)"


_VERIFICATION_TOKEN_SECRET_ROLE = _SecretRole(
    setting_name="verification_token_secret",
    protected_surface="email-verification JWT signing",
    audiences=(VERIFY_TOKEN_AUDIENCE,),
)
_RESET_PASSWORD_TOKEN_SECRET_ROLE = _SecretRole(
    setting_name="reset_password_token_secret",
    protected_surface="reset-password JWT signing and password fingerprints",
    audiences=(RESET_PASSWORD_TOKEN_AUDIENCE,),
)
_TOTP_SECRET_KEY_ROLE = _SecretRole(
    setting_name="totp_secret_key",
    protected_surface="persisted TOTP secret encryption at rest",
)
_TOTP_PENDING_SECRET_ROLE = _SecretRole(
    setting_name="totp_pending_secret",
    protected_surface="pending/enrollment TOTP JWT signing",
    audiences=(TOTP_PENDING_AUDIENCE, TOTP_ENROLL_AUDIENCE),
)


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

    if not unsafe_testing:
        validate_secret_length(secret, label=label)

    return secret


def validate_secret_roles_are_distinct(
    *,
    verification_token_secret: str | None,
    reset_password_token_secret: str | None,
    totp_secret_key: str | None = None,
    totp_pending_secret: str | None = None,
) -> None:
    """Raise when one configured secret value is reused across distinct auth roles.

    Distinct JWT audiences already keep verification, reset-password, and TOTP
    tokens scoped to their own flows. Production deployments must still keep
    those secrets separate so one compromise does not widen the blast radius
    across multiple roles.

    Raises:
        ConfigurationError: If one configured secret value is reused across
            multiple roles.
    """
    configured_roles = (
        (_VERIFICATION_TOKEN_SECRET_ROLE, verification_token_secret),
        (_RESET_PASSWORD_TOKEN_SECRET_ROLE, reset_password_token_secret),
        (_TOTP_SECRET_KEY_ROLE, totp_secret_key),
        (_TOTP_PENDING_SECRET_ROLE, totp_pending_secret),
    )
    roles_by_secret: dict[str, list[_SecretRole]] = {}
    for role, secret in configured_roles:
        if not secret:
            continue
        roles_by_secret.setdefault(secret, []).append(role)

    reused_roles = [
        tuple(sorted(roles, key=lambda current_role: current_role.setting_name))
        for roles in roles_by_secret.values()
        if len(roles) > 1
    ]
    if not reused_roles:
        return

    reused_roles.sort(key=lambda roles: tuple(role.setting_name for role in roles))
    role_descriptions = "; ".join(", ".join(role.render_usage() for role in roles) for roles in reused_roles)
    msg = (
        "Distinct secrets/keys are the supported production posture for "
        "verification, reset-password, and TOTP roles. Distinct JWT audiences "
        "still prevent token cross-use, but reusing one configured value across "
        "roles increases blast radius if that secret leaks. "
        f"Detected shared secret material across: {role_descriptions}. "
        "Configure one distinct high-entropy value for each secret role, or use "
        "unsafe_testing=True only for test-owned single-process setups."
    )
    raise ConfigurationError(msg)


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
