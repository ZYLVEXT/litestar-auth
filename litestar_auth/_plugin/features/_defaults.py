"""Canonical plugin feature defaults."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import timedelta
from typing import TYPE_CHECKING, Literal

from litestar_auth.authentication.strategy._api_key_format import API_KEY_PREFIX
from litestar_auth.config import UNSET, UnsetType

if TYPE_CHECKING:
    from litestar_auth.totp import TotpAlgorithm

type ApiKeyLastUsedWriteStrategy = Literal["disabled", "immediate", "throttled"]
type FeatureKey = Literal["database_token", "api_key", "totp", "oauth"]
type TotpStepUpPolicyMode = Literal["required_when_enrolled", "always_required", "off"]

DATABASE_TOKEN_FEATURE: FeatureKey = "database_token"  # noqa: S105
API_KEY_FEATURE: FeatureKey = "api_key"
TOTP_FEATURE: FeatureKey = "totp"
OAUTH_FEATURE: FeatureKey = "oauth"


@dataclass(frozen=True, slots=True)
class DatabaseTokenDefaults:
    """Canonical DB-token preset defaults."""

    backend_name: str = "database"
    max_age: timedelta = timedelta(hours=1)
    refresh_max_age: timedelta = timedelta(days=30)
    token_bytes: int = 32


@dataclass(frozen=True, slots=True)
class ApiKeyDefaults:
    """Canonical API-key feature defaults."""

    backend_name: str = "api_key"
    prefix: str = API_KEY_PREFIX
    environment_marker: str = "prod"
    max_keys_per_user: int = 20
    default_ttl: timedelta | None = timedelta(days=365)
    require_step_up_on_create: bool = True
    last_used_write_strategy: ApiKeyLastUsedWriteStrategy = "throttled"
    last_used_throttle_seconds: int = 60
    signing_enabled: bool = False
    signing_skew_seconds: int = 300
    signed_body_max_bytes: int = 1024 * 1024
    signed_body_max_messages: int = 1024


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


@dataclass(frozen=True, slots=True)
class FeatureDefaults:
    """Single default source for plugin-owned feature config."""

    database_token: DatabaseTokenDefaults = field(default_factory=DatabaseTokenDefaults)
    api_key: ApiKeyDefaults = field(default_factory=ApiKeyDefaults)
    totp: TotpDefaults = field(default_factory=TotpDefaults)
    oauth: OAuthDefaults = field(default_factory=OAuthDefaults)


FEATURE_DEFAULTS = FeatureDefaults()
DEFAULT_DATABASE_TOKEN_BACKEND_NAME = FEATURE_DEFAULTS.database_token.backend_name
DEFAULT_DATABASE_TOKEN_MAX_AGE = FEATURE_DEFAULTS.database_token.max_age
DEFAULT_DATABASE_TOKEN_REFRESH_MAX_AGE = FEATURE_DEFAULTS.database_token.refresh_max_age
DEFAULT_DATABASE_TOKEN_BYTES = FEATURE_DEFAULTS.database_token.token_bytes
DEFAULT_API_KEY_BACKEND_NAME = FEATURE_DEFAULTS.api_key.backend_name
DEFAULT_API_KEY_TTL = FEATURE_DEFAULTS.api_key.default_ttl
DEFAULT_API_KEY_MAX_KEYS_PER_USER = FEATURE_DEFAULTS.api_key.max_keys_per_user
DEFAULT_API_KEY_LAST_USED_THROTTLE_SECONDS = FEATURE_DEFAULTS.api_key.last_used_throttle_seconds
DEFAULT_API_KEY_SIGNED_BODY_MAX_BYTES = FEATURE_DEFAULTS.api_key.signed_body_max_bytes
DEFAULT_API_KEY_SIGNED_BODY_MAX_MESSAGES = FEATURE_DEFAULTS.api_key.signed_body_max_messages
DEFAULT_TOTP_STEPUP_TTL_SECONDS = FEATURE_DEFAULTS.totp.stepup_ttl_seconds
TOTP_STEPUP_POLICY_ENDPOINTS = frozenset(
    {
        "totp.enable",
        "totp.disable",
        "totp.regenerate_recovery_codes",
        "api_keys.create",
        "api_keys.update",
        "api_keys.revoke",
        "users.update",
        "users.delete",
        "users.update_self",
        "oauth.associate",
    },
)
