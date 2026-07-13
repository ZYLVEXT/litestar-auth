"""Plugin feature configuration dataclasses."""

from __future__ import annotations

from collections.abc import Callable, Sequence
from dataclasses import dataclass, field
from datetime import timedelta  # noqa: TC003
from typing import TYPE_CHECKING, Any

from sqlalchemy.ext.asyncio import AsyncSession

from litestar_auth._plugin.features._defaults import (
    FEATURE_DEFAULTS,
    ApiKeyLastUsedWriteStrategy,
    OrganizationRolePrecedence,
)
from litestar_auth._tenant_resolution import ClaimTenantResolver, HeaderTenantResolver
from litestar_auth.exceptions import ConfigurationError

if TYPE_CHECKING:
    from collections.abc import Mapping

    from litestar.connection import ASGIConnection

    from litestar_auth._tenant_resolution import TenantResolver
    from litestar_auth.authentication.strategy.jwt import JWTDenylistStore
    from litestar_auth.config import OAuthProviderConfig
    from litestar_auth.db import BaseApiKeyStore, BaseOrganizationStore
    from litestar_auth.manager import FernetKeyringConfig
    from litestar_auth.totp import TotpAlgorithm, TotpEnrollmentStore, UsedTotpCodeStore

type ApiKeyStoreFactory = Callable[[AsyncSession], BaseApiKeyStore[Any, Any]]
type OrganizationStoreFactory = Callable[[AsyncSession], BaseOrganizationStore[Any, Any, Any, Any]]
type ApiKeyScopeAuthority = Callable[[ASGIConnection[Any, Any, Any, Any], frozenset[str]], bool]


@dataclass(slots=True)
class TotpConfig:
    """TOTP-specific plugin settings."""

    totp_pending_secret: str = field(repr=False)
    totp_backend_name: str | None = None
    totp_issuer: str = FEATURE_DEFAULTS.totp.issuer
    totp_algorithm: TotpAlgorithm = FEATURE_DEFAULTS.totp.algorithm
    totp_used_tokens_store: UsedTotpCodeStore | None = None
    totp_pending_jti_store: JWTDenylistStore | None = None
    totp_enrollment_store: TotpEnrollmentStore | None = None
    totp_require_replay_protection: bool = FEATURE_DEFAULTS.totp.require_replay_protection
    totp_enable_requires_password: bool = FEATURE_DEFAULTS.totp.enable_requires_password
    totp_pending_require_client_binding: bool = FEATURE_DEFAULTS.totp.pending_require_client_binding


@dataclass(slots=True)
class OAuthConfig:
    """OAuth-specific plugin settings."""

    oauth_cookie_secure: bool = FEATURE_DEFAULTS.oauth.cookie_secure
    oauth_providers: Sequence[OAuthProviderConfig] | None = None
    oauth_provider_scopes: Mapping[str, Sequence[str]] = field(default_factory=dict)
    oauth_associate_by_email: bool = FEATURE_DEFAULTS.oauth.associate_by_email
    oauth_trust_provider_email_verified: bool = FEATURE_DEFAULTS.oauth.trust_provider_email_verified
    include_oauth_associate: bool = FEATURE_DEFAULTS.oauth.include_associate
    oauth_redirect_base_url: str = FEATURE_DEFAULTS.oauth.redirect_base_url
    oauth_redirect_dns_strict: bool = FEATURE_DEFAULTS.oauth.redirect_dns_strict
    oauth_token_encryption_key: str | None = field(default=None, repr=False)
    oauth_token_encryption_keyring: FernetKeyringConfig | None = field(default=None, repr=False)
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
        """Whether OAuth token-at-rest encryption material is configured."""
        return self.oauth_token_encryption_key is not None or self.oauth_token_encryption_keyring is not None


@dataclass(slots=True)
class ApiKeyConfig:
    """API-key plugin backend settings."""

    enabled: bool = False
    store_factory: ApiKeyStoreFactory | None = None
    backend_name: str = FEATURE_DEFAULTS.api_key.backend_name
    prefix: str = FEATURE_DEFAULTS.api_key.prefix
    environment_marker: str = FEATURE_DEFAULTS.api_key.environment_marker
    max_keys_per_user: int = FEATURE_DEFAULTS.api_key.max_keys_per_user
    default_ttl: timedelta | None = FEATURE_DEFAULTS.api_key.default_ttl
    require_step_up_on_create: bool = FEATURE_DEFAULTS.api_key.require_step_up_on_create
    allowed_scopes: Sequence[str] = field(default_factory=tuple)
    scope_subset_check: bool = True
    scope_authority: ApiKeyScopeAuthority | None = None
    last_used_write_strategy: ApiKeyLastUsedWriteStrategy = FEATURE_DEFAULTS.api_key.last_used_write_strategy
    last_used_throttle_seconds: int = FEATURE_DEFAULTS.api_key.last_used_throttle_seconds
    signing_enabled: bool = FEATURE_DEFAULTS.api_key.signing_enabled
    signing_skew_seconds: int = FEATURE_DEFAULTS.api_key.signing_skew_seconds
    signed_body_max_bytes: int = FEATURE_DEFAULTS.api_key.signed_body_max_bytes
    signed_body_max_messages: int = FEATURE_DEFAULTS.api_key.signed_body_max_messages
    nonce_store: object | None = None
    secret_encryption_keyring: FernetKeyringConfig | None = field(default=None, repr=False)


@dataclass(slots=True)
class OrganizationConfig:
    """Organization feature settings."""

    enabled: bool = False
    store_factory: OrganizationStoreFactory | None = None
    include_switch_organization: bool = FEATURE_DEFAULTS.organization.include_switch_organization
    include_organization_admin: bool = FEATURE_DEFAULTS.organization.include_organization_admin
    include_organization_invitations: bool = FEATURE_DEFAULTS.organization.include_organization_invitations
    slug_min_length: int = FEATURE_DEFAULTS.organization.slug_min_length
    slug_max_length: int = FEATURE_DEFAULTS.organization.slug_max_length
    tenant_header_name: str = FEATURE_DEFAULTS.organization.tenant_header_name
    tenant_resolver: TenantResolver | None = None
    role_precedence: OrganizationRolePrecedence = FEATURE_DEFAULTS.organization.role_precedence
    require_authorization_context: bool = FEATURE_DEFAULTS.organization.require_authorization_context

    def __post_init__(self) -> None:
        """Resolve the default tenant resolver from the configured header name."""
        if self.tenant_resolver is None:
            self.tenant_resolver = (
                ClaimTenantResolver()
                if self.include_switch_organization
                else HeaderTenantResolver(header_name=self.tenant_header_name)
            )


@dataclass(slots=True)
class DatabaseTokenAuthConfig:
    """DB-token bearer preset settings owned by ``LitestarAuthConfig``."""

    token_hash_secret: str = field(repr=False)
    backend_name: str = FEATURE_DEFAULTS.database_token.backend_name
    max_age: timedelta = FEATURE_DEFAULTS.database_token.max_age
    refresh_max_age: timedelta = FEATURE_DEFAULTS.database_token.refresh_max_age
    token_bytes: int = FEATURE_DEFAULTS.database_token.token_bytes
