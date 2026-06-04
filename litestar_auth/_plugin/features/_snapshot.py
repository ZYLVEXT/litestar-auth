"""Resolved plugin feature snapshot contracts."""

from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from litestar_auth._plugin.features._config import (
        ApiKeyConfig,
        DatabaseTokenAuthConfig,
        OAuthConfig,
        OrganizationConfig,
        TotpConfig,
    )
    from litestar_auth.config import UnsetType


@dataclass(frozen=True, slots=True)
class FeatureConfigSnapshot:
    """Immutable snapshot of plugin feature configuration inputs."""

    database_token_auth: DatabaseTokenAuthConfig | None
    api_keys: ApiKeyConfig
    totp_config: TotpConfig | None
    oauth_config: OAuthConfig | None
    organization_config: OrganizationConfig


@dataclass(frozen=True, slots=True)
class ResolvedDatabaseTokenDefaults:
    """Resolved DB-token feature defaults for one plugin config."""

    config: DatabaseTokenAuthConfig | None
    backend_name: str | UnsetType


@dataclass(frozen=True, slots=True)
class ResolvedApiKeyDefaults:
    """Resolved API-key feature defaults for one plugin config."""

    config: ApiKeyConfig
    enabled: bool
    backend_name: str
    hash_secret: str | UnsetType


@dataclass(frozen=True, slots=True)
class ResolvedTotpDefaults:
    """Resolved TOTP feature defaults for one plugin config."""

    config: TotpConfig | None
    backend_name: str | UnsetType
    stepup_ttl_seconds: int
    stepup_allow_recovery: bool


@dataclass(frozen=True, slots=True)
class ResolvedOAuthDefaults:
    """Resolved OAuth feature defaults for one plugin config."""

    config: OAuthConfig | None


@dataclass(frozen=True, slots=True)
class ResolvedOrganizationDefaults:
    """Resolved organization feature defaults for one plugin config."""

    config: OrganizationConfig
    enabled: bool


@dataclass(frozen=True, slots=True)
class ResolvedFeatureDefaults:
    """Single resolved-defaults snapshot consumed by plugin startup."""

    config_snapshot: FeatureConfigSnapshot
    database_token: ResolvedDatabaseTokenDefaults
    api_key: ResolvedApiKeyDefaults
    totp: ResolvedTotpDefaults
    oauth: ResolvedOAuthDefaults
    organization: ResolvedOrganizationDefaults
