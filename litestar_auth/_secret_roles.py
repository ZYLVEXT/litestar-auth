"""Secret-role catalog and distinctness validation."""

from __future__ import annotations

from dataclasses import dataclass

from litestar_auth.exceptions import ConfigurationError

VERIFY_TOKEN_AUDIENCE = "litestar-auth:verify"
RESET_PASSWORD_TOKEN_AUDIENCE = "litestar-auth:reset-password"
JWT_ACCESS_TOKEN_AUDIENCE = "litestar-auth:access"
TOTP_PENDING_AUDIENCE = "litestar-auth:2fa-pending"
TOTP_ENROLL_AUDIENCE = "litestar-auth:2fa-enroll"


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
_LOGIN_IDENTIFIER_TELEMETRY_SECRET_ROLE = _SecretRole(
    setting_name="login_identifier_telemetry_secret",
    protected_surface="failed-login identifier digest telemetry",
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
_OAUTH_FLOW_COOKIE_SECRET_ROLE = _SecretRole(
    setting_name="oauth_flow_cookie_secret",
    protected_surface="transient OAuth state and PKCE verifier cookie encryption",
)


@dataclass(frozen=True, slots=True)
class SecretRoleValues:
    """Configured secret material grouped by the auth role each value protects."""

    verification_token_secret: str | None
    reset_password_token_secret: str | None
    login_identifier_telemetry_secret: str | None = None
    totp_secret_key: str | None = None
    totp_pending_secret: str | None = None
    oauth_flow_cookie_secret: str | None = None

    def as_role_pairs(self) -> tuple[tuple[_SecretRole, str | None], ...]:
        """Return role metadata paired with the configured secret material."""
        return (
            (_VERIFICATION_TOKEN_SECRET_ROLE, self.verification_token_secret),
            (_RESET_PASSWORD_TOKEN_SECRET_ROLE, self.reset_password_token_secret),
            (_LOGIN_IDENTIFIER_TELEMETRY_SECRET_ROLE, self.login_identifier_telemetry_secret),
            (_TOTP_SECRET_KEY_ROLE, self.totp_secret_key),
            (_TOTP_PENDING_SECRET_ROLE, self.totp_pending_secret),
            (_OAUTH_FLOW_COOKIE_SECRET_ROLE, self.oauth_flow_cookie_secret),
        )


def validate_secret_roles_are_distinct(role_values: SecretRoleValues) -> None:
    """Raise when one configured secret value is reused across distinct auth roles.

    Distinct JWT audiences already keep verification, reset-password, and TOTP
    tokens scoped to their own flows. Production deployments must still keep
    those secrets separate so one compromise does not widen the blast radius
    across multiple roles.

    Raises:
        ConfigurationError: If one configured secret value is reused across
            multiple roles.
    """
    roles_by_secret: dict[str, list[_SecretRole]] = {}
    for role, secret in role_values.as_role_pairs():
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
        "verification, reset-password, login telemetry, TOTP, and OAuth flow-cookie roles. "
        "Distinct JWT audiences "
        "and encrypted-cookie envelopes still prevent token cross-use, but reusing one configured value across "
        "roles increases blast radius if that secret leaks. "
        f"Detected shared secret material across: {role_descriptions}. "
        "Configure one distinct high-entropy value for each secret role, or use "
        "unsafe_testing=True only for test-owned single-process setups."
    )
    raise ConfigurationError(msg)
