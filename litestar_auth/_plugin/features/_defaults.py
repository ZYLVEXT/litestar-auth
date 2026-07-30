"""Canonical plugin feature defaults."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import timedelta
from typing import TYPE_CHECKING, Literal

from litestar_auth._tenant_resolution import DEFAULT_ORGANIZATION_HEADER
from litestar_auth.config import UNSET, UnsetType

if TYPE_CHECKING:
    from litestar_auth.totp import TotpAlgorithm

OrganizationRolePrecedence = Literal["replace", "merge"]
type FeatureKey = Literal["database_token", "totp", "oauth", "organization"]
type TotpStepUpPolicyMode = Literal["required_when_enrolled", "always_required", "off"]

DATABASE_TOKEN_FEATURE: FeatureKey = "database_token"  # ruff: ignore[hardcoded-password-string]
TOTP_FEATURE: FeatureKey = "totp"
OAUTH_FEATURE: FeatureKey = "oauth"
ORGANIZATION_FEATURE: FeatureKey = "organization"


@dataclass(frozen=True, slots=True)
class DatabaseTokenDefaults:
    """Canonical DB-token preset defaults."""

    backend_name: str = "database"
    max_age: timedelta = timedelta(hours=1)
    refresh_max_age: timedelta = timedelta(days=30)
    token_bytes: int = 32


@dataclass(frozen=True, slots=True)
class TotpDefaults:
    """Canonical TOTP feature defaults."""

    backend_name: UnsetType = UNSET
    issuer: str = "litestar-auth"
    algorithm: TotpAlgorithm = "SHA256"
    require_replay_protection: bool = True
    enable_requires_password: bool = True
    pending_require_client_binding: bool = True
    stepup_ttl_seconds: int = 300
    stepup_allow_recovery: bool = False


@dataclass(frozen=True, slots=True)
class OAuthDefaults:
    """Canonical OAuth feature defaults."""

    cookie_secure: bool = True
    associate_by_email: bool = False
    trust_provider_email_verified: bool = False
    include_associate: bool = False
    redirect_base_url: str = ""
    # Fail closed by default: DNS resolver failures or empty/unusable answers for
    # the OAuth redirect host reject startup rather than silently accepting an
    # unresolvable/SSRF-adjacent origin. Operators in offline or sandboxed startup
    # environments opt back into fail-open with oauth_redirect_dns_strict=False.
    redirect_dns_strict: bool = True


@dataclass(frozen=True, slots=True)
class OrganizationDefaults:
    """Canonical organization feature defaults."""

    include_organization_admin: bool = False
    include_organization_invitations: bool = False
    slug_min_length: int = 1
    slug_max_length: int = 128
    tenant_header_name: str = DEFAULT_ORGANIZATION_HEADER
    role_precedence: OrganizationRolePrecedence = "replace"
    require_authorization_context: bool = False


@dataclass(frozen=True, slots=True)
class FeatureDefaults:
    """Single default source for plugin-owned feature config."""

    database_token: DatabaseTokenDefaults = field(default_factory=DatabaseTokenDefaults)
    totp: TotpDefaults = field(default_factory=TotpDefaults)
    oauth: OAuthDefaults = field(default_factory=OAuthDefaults)
    organization: OrganizationDefaults = field(default_factory=OrganizationDefaults)


FEATURE_DEFAULTS = FeatureDefaults()
DEFAULT_DATABASE_TOKEN_BACKEND_NAME = FEATURE_DEFAULTS.database_token.backend_name
DEFAULT_DATABASE_TOKEN_MAX_AGE = FEATURE_DEFAULTS.database_token.max_age
DEFAULT_DATABASE_TOKEN_REFRESH_MAX_AGE = FEATURE_DEFAULTS.database_token.refresh_max_age
DEFAULT_DATABASE_TOKEN_BYTES = FEATURE_DEFAULTS.database_token.token_bytes
DEFAULT_TOTP_STEPUP_TTL_SECONDS = FEATURE_DEFAULTS.totp.stepup_ttl_seconds
TOTP_STEPUP_POLICY_ENDPOINTS = frozenset(
    {
        "totp.enable",
        "totp.disable",
        "totp.regenerate_recovery_codes",
        "users.update",
        "users.delete",
        "users.update_self",
        "oauth.associate",
    },
)
