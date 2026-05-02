"""Feature-specific plugin configuration contracts."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import timedelta
from typing import TYPE_CHECKING

from litestar_auth.exceptions import ConfigurationError

if TYPE_CHECKING:
    from collections.abc import Mapping, Sequence

    from litestar_auth.authentication.strategy.jwt import JWTDenylistStore
    from litestar_auth.config import OAuthProviderConfig
    from litestar_auth.manager import FernetKeyringConfig
    from litestar_auth.totp import TotpAlgorithm, TotpEnrollmentStore, UsedTotpCodeStore

DEFAULT_DATABASE_TOKEN_BACKEND_NAME = "database"  # noqa: S105
DEFAULT_DATABASE_TOKEN_MAX_AGE = timedelta(hours=1)
DEFAULT_DATABASE_TOKEN_REFRESH_MAX_AGE = timedelta(days=30)
DEFAULT_DATABASE_TOKEN_BYTES = 32


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
class DatabaseTokenAuthConfig:
    """DB-token bearer preset settings owned by ``LitestarAuthConfig``."""

    # Security: HMAC token-hash material must stay out of repr/str output.
    token_hash_secret: str = field(repr=False)
    backend_name: str = DEFAULT_DATABASE_TOKEN_BACKEND_NAME
    max_age: timedelta = DEFAULT_DATABASE_TOKEN_MAX_AGE
    refresh_max_age: timedelta = DEFAULT_DATABASE_TOKEN_REFRESH_MAX_AGE
    token_bytes: int = DEFAULT_DATABASE_TOKEN_BYTES
