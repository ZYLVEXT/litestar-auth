"""Central configuration helpers for litestar-auth.

This module contains small, shared primitives used across the library to keep
security-relevant validation consistent, including secret-length checks and
explicit unsafe-testing overrides.
"""

from __future__ import annotations

import secrets
import warnings
from contextlib import contextmanager
from contextvars import ContextVar
from dataclasses import dataclass
from typing import TYPE_CHECKING

from litestar_auth.exceptions import ConfigurationError

if TYPE_CHECKING:
    from collections.abc import Iterator

MINIMUM_SECRET_LENGTH = 32
# Shared password-length bounds for built-in validation and schema metadata.
DEFAULT_MINIMUM_PASSWORD_LENGTH = 12
MAX_PASSWORD_LENGTH = 128
# Canonical JWT audiences shared across account, auth, and TOTP flows.
VERIFY_TOKEN_AUDIENCE = "litestar-auth:verify"
RESET_PASSWORD_TOKEN_AUDIENCE = "litestar-auth:reset-password"
JWT_ACCESS_TOKEN_AUDIENCE = "litestar-auth:access"
TOTP_PENDING_AUDIENCE = "litestar-auth:2fa-pending"
TOTP_ENROLL_AUDIENCE = "litestar-auth:2fa-enroll"
type OAuthProviderConfig = tuple[str, object]


@dataclass(frozen=True, slots=True)
class _SecretRole:
    """Describe one configured secret-bearing role and the flow it protects."""

    setting_name: str
    protected_surface: str
    audiences: tuple[str, ...] = ()

    def render_usage(self) -> str:
        """Return one human-readable description for warnings and docs."""
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


@dataclass(frozen=True, slots=True)
class _PluginSecretRoleWarningState:
    """Track the plugin-managed secret surface already covered by validation."""

    verification_token_secret: str | None = None
    reset_password_token_secret: str | None = None
    totp_secret_key: str | None = None


_PLUGIN_SECRET_ROLE_WARNING_OWNER = ContextVar[_PluginSecretRoleWarningState | None](
    "litestar_auth_plugin_secret_role_warning_owner",
    default=None,
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


def warn_if_secret_roles_are_reused(
    *,
    verification_token_secret: str | None,
    reset_password_token_secret: str | None,
    totp_secret_key: str | None = None,
    totp_pending_secret: str | None = None,
    warning_options: tuple[type[Warning], int] = (UserWarning, 2),
) -> None:
    """Warn when one configured secret value is reused across distinct auth roles.

    Distinct JWT audiences already keep verification, reset-password, and TOTP
    tokens scoped to their own flows. The warning exists because production
    deployments should still keep those secrets separate so one compromise does
    not widen the blast radius across multiple roles.
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
    warning_cls, warning_stacklevel = warning_options
    warnings.warn(
        "Distinct secrets/keys are the supported production posture for "
        "verification, reset-password, and TOTP roles. Distinct JWT audiences "
        "still prevent token cross-use, but reusing one configured value across "
        "roles increases blast radius if that secret leaks. "
        f"Detected shared secret material across: {role_descriptions}. "
        "Current releases only warn to preserve compatibility; future major "
        "releases may reject reused secret material.",
        warning_cls,
        stacklevel=warning_stacklevel,
    )


def plugin_owns_secret_role_reuse_warning() -> bool:
    """Return whether the current plugin-managed secret surface already owns the reuse warning."""
    return _PLUGIN_SECRET_ROLE_WARNING_OWNER.get() is not None


def plugin_secret_role_warning_matches_manager_surface(
    *,
    verification_token_secret: str,
    reset_password_token_secret: str,
    totp_secret_key: str | None,
) -> bool:
    """Return whether the current manager secrets match the plugin-owned baseline."""
    state = _PLUGIN_SECRET_ROLE_WARNING_OWNER.get()
    if state is None:
        return False

    return state == _PluginSecretRoleWarningState(
        verification_token_secret=verification_token_secret,
        reset_password_token_secret=reset_password_token_secret,
        totp_secret_key=totp_secret_key,
    )


@contextmanager
def plugin_secret_role_warning_owner(
    *,
    verification_token_secret: str | None = None,
    reset_password_token_secret: str | None = None,
    totp_secret_key: str | None = None,
) -> Iterator[None]:
    """Mark the current plugin-managed secret surface as already covered by validation."""
    token = _PLUGIN_SECRET_ROLE_WARNING_OWNER.set(
        _PluginSecretRoleWarningState(
            verification_token_secret=verification_token_secret,
            reset_password_token_secret=reset_password_token_secret,
            totp_secret_key=totp_secret_key,
        ),
    )
    try:
        yield
    finally:
        _PLUGIN_SECRET_ROLE_WARNING_OWNER.reset(token)


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
