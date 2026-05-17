"""Feature-specific plugin configuration contracts."""

from __future__ import annotations

from collections.abc import Callable, Sequence
from dataclasses import dataclass, field
from datetime import timedelta
from typing import TYPE_CHECKING, Any, Literal

from sqlalchemy.ext.asyncio import AsyncSession

from litestar_auth.authentication.strategy._api_key_format import API_KEY_PREFIX
from litestar_auth.exceptions import ConfigurationError

if TYPE_CHECKING:
    from collections.abc import Mapping

    from litestar.connection import ASGIConnection

    from litestar_auth.authentication.strategy.jwt import JWTDenylistStore
    from litestar_auth.config import OAuthProviderConfig
    from litestar_auth.db import BaseApiKeyStore
    from litestar_auth.manager import FernetKeyringConfig
    from litestar_auth.totp import TotpAlgorithm, TotpEnrollmentStore, UsedTotpCodeStore

type ApiKeyStoreFactory = Callable[[AsyncSession], BaseApiKeyStore[Any, Any]]
type ApiKeyScopeAuthority = Callable[[ASGIConnection[Any, Any, Any, Any], frozenset[str]], bool]
type ApiKeyLastUsedWriteStrategy = Literal["disabled", "immediate", "throttled"]
type TotpStepUpPolicyMode = Literal["required_when_enrolled", "always_required", "off"]

DEFAULT_DATABASE_TOKEN_BACKEND_NAME = "database"  # noqa: S105
DEFAULT_DATABASE_TOKEN_MAX_AGE = timedelta(hours=1)
DEFAULT_DATABASE_TOKEN_REFRESH_MAX_AGE = timedelta(days=30)
DEFAULT_DATABASE_TOKEN_BYTES = 32
DEFAULT_API_KEY_BACKEND_NAME = "api_key"
DEFAULT_API_KEY_TTL = timedelta(days=365)
DEFAULT_API_KEY_MAX_KEYS_PER_USER = 20
DEFAULT_API_KEY_LAST_USED_THROTTLE_SECONDS = 60
DEFAULT_API_KEY_SIGNED_BODY_MAX_BYTES = 1024 * 1024
DEFAULT_API_KEY_SIGNED_BODY_MAX_MESSAGES = 1024
DEFAULT_TOTP_STEPUP_TTL_SECONDS = 300
TOTP_STEPUP_POLICY_ENDPOINTS = frozenset(
    {
        "totp.enable",
        "totp.disable",
        "totp.regenerate_recovery_codes",
        "api_keys.create",
        "api_keys.update",
        "api_keys.revoke",
        "users.update_self",
        "oauth.associate",
    },
)


@dataclass(slots=True)
class TotpConfig:
    """TOTP-specific plugin settings.

    Includes recovery-code storage flow configuration and default-on
    pending-token client binding for plugin-owned TOTP routes.
    """

    # Security: hide the pending-token signing secret from debug repr output.
    totp_pending_secret: str = field(repr=False)
    totp_backend_name: str | None = None
    totp_issuer: str = "litestar-auth"
    totp_algorithm: TotpAlgorithm = "SHA256"
    totp_used_tokens_store: UsedTotpCodeStore | None = None
    totp_pending_jti_store: JWTDenylistStore | None = None
    totp_enrollment_store: TotpEnrollmentStore | None = None
    totp_require_replay_protection: bool = True
    totp_enable_requires_password: bool = True
    totp_pending_require_client_binding: bool = True


@dataclass(slots=True)
class OAuthConfig:
    """OAuth-specific plugin settings."""

    oauth_cookie_secure: bool = True
    oauth_providers: Sequence[OAuthProviderConfig] | None = None
    oauth_provider_scopes: Mapping[str, Sequence[str]] = field(default_factory=dict)
    oauth_associate_by_email: bool = False
    oauth_trust_provider_email_verified: bool = False
    include_oauth_associate: bool = False
    oauth_redirect_base_url: str = ""
    # Security: never leak the Fernet key through repr/str when configs are logged.
    oauth_token_encryption_key: str | None = field(default=None, repr=False)
    oauth_token_encryption_keyring: FernetKeyringConfig | None = field(default=None, repr=False)
    # Security: transient state + PKCE verifier material must be encrypted with
    # server-side secret material before it is placed in the browser flow cookie.
    oauth_flow_cookie_secret: str | None = field(default=None, repr=False)

    def __post_init__(self) -> None:
        """Reject ambiguous OAuth token-at-rest key inputs.

        Raises:
            ConfigurationError: If both one-key and keyring inputs are configured.
        """
        if self.oauth_token_encryption_key is None or self.oauth_token_encryption_keyring is None:
            return
        msg = (
            "Configure OAuth token encryption with oauth_token_encryption_key or "
            "oauth_token_encryption_keyring, not both."
        )
        raise ConfigurationError(msg)

    @property
    def has_oauth_token_encryption(self) -> bool:
        """Return whether OAuth token-at-rest encryption material is configured."""
        return self.oauth_token_encryption_key is not None or self.oauth_token_encryption_keyring is not None


@dataclass(slots=True)
class ApiKeyConfig:
    """API-key plugin backend settings."""

    enabled: bool = False
    store_factory: ApiKeyStoreFactory | None = None
    backend_name: str = DEFAULT_API_KEY_BACKEND_NAME
    prefix: str = API_KEY_PREFIX
    environment_marker: str = "prod"
    max_keys_per_user: int = DEFAULT_API_KEY_MAX_KEYS_PER_USER
    default_ttl: timedelta | None = DEFAULT_API_KEY_TTL
    require_step_up_on_create: bool = True
    allowed_scopes: Sequence[str] = field(default_factory=tuple)
    scope_subset_check: bool = True
    scope_authority: ApiKeyScopeAuthority | None = None
    last_used_write_strategy: ApiKeyLastUsedWriteStrategy = "throttled"
    last_used_throttle_seconds: int = DEFAULT_API_KEY_LAST_USED_THROTTLE_SECONDS
    signing_enabled: bool = False
    signing_skew_seconds: int = 300
    signed_body_max_bytes: int = DEFAULT_API_KEY_SIGNED_BODY_MAX_BYTES
    signed_body_max_messages: int = DEFAULT_API_KEY_SIGNED_BODY_MAX_MESSAGES
    nonce_store: object | None = None
    secret_encryption_keyring: FernetKeyringConfig | None = field(default=None, repr=False)


@dataclass(slots=True)
class DatabaseTokenAuthConfig:
    """DB-token bearer preset settings owned by ``LitestarAuthConfig``."""

    # Security: HMAC token-hash material must stay out of repr/str output.
    token_hash_secret: str = field(repr=False)
    backend_name: str = DEFAULT_DATABASE_TOKEN_BACKEND_NAME
    max_age: timedelta = DEFAULT_DATABASE_TOKEN_MAX_AGE
    refresh_max_age: timedelta = DEFAULT_DATABASE_TOKEN_REFRESH_MAX_AGE
    token_bytes: int = DEFAULT_DATABASE_TOKEN_BYTES
