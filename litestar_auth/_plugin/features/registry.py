"""Canonical plugin feature registry and startup backend inventory."""

from __future__ import annotations

from collections.abc import Hashable
from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Any

from litestar_auth._plugin import database_token as _database_token_module
from litestar_auth._plugin.features._backends import StartupBackendInventory, StartupBackendTemplate
from litestar_auth._plugin.features._config import (
    DatabaseTokenAuthConfig,
    OAuthConfig,
    OrganizationConfig,
    OrganizationStoreFactory,
    TotpConfig,
)
from litestar_auth._plugin.features._defaults import (
    DATABASE_TOKEN_FEATURE,
    DEFAULT_DATABASE_TOKEN_BACKEND_NAME,
    DEFAULT_DATABASE_TOKEN_BYTES,
    DEFAULT_DATABASE_TOKEN_MAX_AGE,
    DEFAULT_DATABASE_TOKEN_REFRESH_MAX_AGE,
    DEFAULT_TOTP_STEPUP_TTL_SECONDS,
    FEATURE_DEFAULTS,
    OAUTH_FEATURE,
    ORGANIZATION_FEATURE,
    TOTP_FEATURE,
    TOTP_STEPUP_POLICY_ENDPOINTS,
    DatabaseTokenDefaults,
    FeatureDefaults,
    FeatureKey,
    OAuthDefaults,
    OrganizationDefaults,
    OrganizationRolePrecedence,
    TotpDefaults,
    TotpStepUpPolicyMode,
)
from litestar_auth._plugin.features._snapshot import (
    FeatureConfigSnapshot,
    ResolvedDatabaseTokenDefaults,
    ResolvedFeatureDefaults,
    ResolvedOAuthDefaults,
    ResolvedOrganizationDefaults,
    ResolvedTotpDefaults,
)
from litestar_auth.config import UNSET
from litestar_auth.types import UserProtocol

if TYPE_CHECKING:
    from sqlalchemy.ext.asyncio import AsyncSession

    from litestar_auth._plugin.config import LitestarAuthConfig
    from litestar_auth.authentication.backend import AuthenticationBackend

__all__ = (
    "DATABASE_TOKEN_FEATURE",
    "DEFAULT_DATABASE_TOKEN_BACKEND_NAME",
    "DEFAULT_DATABASE_TOKEN_BYTES",
    "DEFAULT_DATABASE_TOKEN_MAX_AGE",
    "DEFAULT_DATABASE_TOKEN_REFRESH_MAX_AGE",
    "DEFAULT_TOTP_STEPUP_TTL_SECONDS",
    "FEATURE_DEFAULTS",
    "OAUTH_FEATURE",
    "ORGANIZATION_FEATURE",
    "TOTP_FEATURE",
    "TOTP_STEPUP_POLICY_ENDPOINTS",
    "DatabaseTokenAuthConfig",
    "DatabaseTokenDefaults",
    "FeatureConfigSnapshot",
    "FeatureDefaults",
    "FeatureKey",
    "FeatureRegistry",
    "OAuthConfig",
    "OAuthDefaults",
    "OrganizationConfig",
    "OrganizationDefaults",
    "OrganizationRolePrecedence",
    "OrganizationStoreFactory",
    "ResolvedDatabaseTokenDefaults",
    "ResolvedFeatureDefaults",
    "ResolvedOAuthDefaults",
    "ResolvedOrganizationDefaults",
    "ResolvedTotpDefaults",
    "StartupBackendInventory",
    "StartupBackendTemplate",
    "TotpConfig",
    "TotpDefaults",
    "TotpStepUpPolicyMode",
    "resolve_feature_defaults",
    "resolve_feature_registry",
)


@dataclass(frozen=True, slots=True)
class FeatureRegistry[UP: UserProtocol[Any], ID: Hashable]:
    """Resolved plugin feature state for startup, route assembly, and request binding."""

    config_snapshot: FeatureConfigSnapshot
    enabled_features: frozenset[FeatureKey]
    backend_inventory: StartupBackendInventory[UP, ID]
    backend_by_feature: dict[FeatureKey, tuple[int, StartupBackendTemplate[UP, ID]]] = field(default_factory=dict)

    def is_enabled(self, feature: FeatureKey) -> bool:
        """Return whether ``feature`` is enabled in this registry."""
        return feature in self.enabled_features

    def config_for(self, feature: FeatureKey) -> object | None:
        """Return the captured config object for ``feature``."""
        return {
            DATABASE_TOKEN_FEATURE: self.config_snapshot.database_token_auth,
            TOTP_FEATURE: self.config_snapshot.totp_config,
            OAUTH_FEATURE: self.config_snapshot.oauth_config,
            ORGANIZATION_FEATURE: self.config_snapshot.organization_config,
        }[feature]

    def startup_backends(self) -> tuple[StartupBackendTemplate[UP, ID], ...]:
        """Return startup backends from the canonical inventory."""
        return self.backend_inventory.startup_backends()

    def bind_request_backends(self, session: AsyncSession) -> tuple[AuthenticationBackend[UP, ID], ...]:
        """Return request-scoped runtime backends from the canonical inventory."""
        return self.backend_inventory.bind_request_backends(session)


def resolve_feature_registry[UP: UserProtocol[Any], ID: Hashable](
    config: LitestarAuthConfig[UP, ID],
) -> FeatureRegistry[UP, ID]:
    """Return the canonical feature registry for plugin assembly and request binding.

    Raises:
        ValueError: If both ``database_token_auth`` and manual ``backends`` are configured.
    """
    defaults = resolve_feature_defaults(config)
    if defaults.database_token.config is not None and config.backends:
        msg = "Configure authentication backends via database_token_auth=... or backends=..., not both."
        raise ValueError(msg)

    startup_backends = _build_startup_backend_templates(config, defaults=defaults)
    backend_by_feature: dict[FeatureKey, tuple[int, StartupBackendTemplate[UP, ID]]] = {}
    enabled_features: set[FeatureKey] = set()
    if defaults.database_token.config is not None:
        enabled_features.add(DATABASE_TOKEN_FEATURE)
        backend_by_feature[DATABASE_TOKEN_FEATURE] = (0, startup_backends[0])
    if defaults.totp.config is not None:
        enabled_features.add(TOTP_FEATURE)
    if defaults.oauth.config is not None:
        enabled_features.add(OAUTH_FEATURE)
    if defaults.organization.enabled:
        enabled_features.add(ORGANIZATION_FEATURE)

    return FeatureRegistry(
        config_snapshot=defaults.config_snapshot,
        enabled_features=frozenset(enabled_features),
        backend_inventory=StartupBackendInventory(startup_backends),
        backend_by_feature=backend_by_feature,
    )


def resolve_feature_defaults[UP: UserProtocol[Any], ID: Hashable](
    config: LitestarAuthConfig[UP, ID],
) -> ResolvedFeatureDefaults:
    """Resolve omitted feature settings into one startup snapshot.

    ``None`` remains an explicit value on public config dataclasses where it has
    product meaning. Internally, omitted fallback targets are normalized to
    :data:`UNSET` here so startup code does not reimplement ad-hoc
    ``None``-means-default branches.

    Returns:
        Resolved feature defaults for startup wiring.
    """
    database_token_config = config.database_token_auth
    totp_config = config.totp_config
    totp_backend_name = None if totp_config is None else getattr(totp_config, "totp_backend_name", None)
    oauth_config = config.oauth_config
    organization_config = config.organization_config
    return ResolvedFeatureDefaults(
        config_snapshot=FeatureConfigSnapshot(
            database_token_auth=database_token_config,
            totp_config=totp_config,
            oauth_config=oauth_config,
            organization_config=organization_config,
        ),
        database_token=ResolvedDatabaseTokenDefaults(
            config=database_token_config,
            backend_name=UNSET if database_token_config is None else database_token_config.backend_name,
        ),
        totp=ResolvedTotpDefaults(
            config=totp_config,
            backend_name=UNSET if totp_backend_name is None else totp_backend_name,
            stepup_ttl_seconds=config.totp_stepup_ttl_seconds,
            stepup_allow_recovery=config.totp_stepup_allow_recovery,
        ),
        oauth=ResolvedOAuthDefaults(config=oauth_config),
        organization=ResolvedOrganizationDefaults(config=organization_config, enabled=organization_config.enabled),
    )


def _build_startup_backend_templates[UP: UserProtocol[Any], ID: Hashable](
    config: LitestarAuthConfig[UP, ID],
    *,
    defaults: ResolvedFeatureDefaults,
) -> tuple[StartupBackendTemplate[UP, ID], ...]:
    startup_backends: tuple[StartupBackendTemplate[UP, ID], ...]
    if defaults.database_token.config is not None:
        startup_backends = (
            _database_token_module._build_database_token_backend_template(  # ruff: ignore[private-member-access]
                defaults.database_token.config,
                unsafe_testing=config.unsafe_testing,
            ),
        )
    else:
        startup_backends = tuple(StartupBackendTemplate.from_runtime_backend(backend) for backend in config.backends)

    return startup_backends
