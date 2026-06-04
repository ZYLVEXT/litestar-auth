"""Canonical plugin feature registry and startup backend inventory."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Any

from litestar_auth._plugin.features._backends import StartupBackendInventory, StartupBackendTemplate
from litestar_auth._plugin.features._config import (
    ApiKeyConfig,
    ApiKeyScopeAuthority,
    ApiKeyStoreFactory,
    DatabaseTokenAuthConfig,
    OAuthConfig,
    OrganizationConfig,
    OrganizationStoreFactory,
    TotpConfig,
)
from litestar_auth._plugin.features._defaults import (
    API_KEY_FEATURE,
    DATABASE_TOKEN_FEATURE,
    DEFAULT_API_KEY_BACKEND_NAME,
    DEFAULT_API_KEY_LAST_USED_THROTTLE_SECONDS,
    DEFAULT_API_KEY_MAX_KEYS_PER_USER,
    DEFAULT_API_KEY_SIGNED_BODY_MAX_BYTES,
    DEFAULT_API_KEY_SIGNED_BODY_MAX_MESSAGES,
    DEFAULT_API_KEY_TTL,
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
    ApiKeyDefaults,
    ApiKeyLastUsedWriteStrategy,
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
    ResolvedApiKeyDefaults,
    ResolvedDatabaseTokenDefaults,
    ResolvedFeatureDefaults,
    ResolvedOAuthDefaults,
    ResolvedOrganizationDefaults,
    ResolvedTotpDefaults,
)
from litestar_auth.config import UNSET, UnsetType
from litestar_auth.types import UserProtocol

if TYPE_CHECKING:
    from sqlalchemy.ext.asyncio import AsyncSession

    from litestar_auth._plugin.config import LitestarAuthConfig
    from litestar_auth.authentication.backend import AuthenticationBackend

__all__ = (
    "API_KEY_FEATURE",
    "DATABASE_TOKEN_FEATURE",
    "DEFAULT_API_KEY_BACKEND_NAME",
    "DEFAULT_API_KEY_LAST_USED_THROTTLE_SECONDS",
    "DEFAULT_API_KEY_MAX_KEYS_PER_USER",
    "DEFAULT_API_KEY_SIGNED_BODY_MAX_BYTES",
    "DEFAULT_API_KEY_SIGNED_BODY_MAX_MESSAGES",
    "DEFAULT_API_KEY_TTL",
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
    "ApiKeyConfig",
    "ApiKeyDefaults",
    "ApiKeyLastUsedWriteStrategy",
    "ApiKeyScopeAuthority",
    "ApiKeyStoreFactory",
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
    "ResolvedApiKeyDefaults",
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
class FeatureRegistry[UP: UserProtocol[Any], ID]:
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
            API_KEY_FEATURE: self.config_snapshot.api_keys,
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


def resolve_feature_registry[UP: UserProtocol[Any], ID](
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
    if defaults.api_key.enabled:
        enabled_features.add(API_KEY_FEATURE)
        api_key_backend = _find_backend_by_name(startup_backends, defaults.api_key.backend_name)
        if api_key_backend is not None:
            backend_by_feature[API_KEY_FEATURE] = api_key_backend
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


def resolve_feature_defaults[UP: UserProtocol[Any], ID](
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
    api_key_config = config.api_keys
    totp_config = config.totp_config
    totp_backend_name = None if totp_config is None else getattr(totp_config, "totp_backend_name", None)
    oauth_config = config.oauth_config
    organization_config = config.organization_config
    return ResolvedFeatureDefaults(
        config_snapshot=FeatureConfigSnapshot(
            database_token_auth=database_token_config,
            api_keys=api_key_config,
            totp_config=totp_config,
            oauth_config=oauth_config,
            organization_config=organization_config,
        ),
        database_token=ResolvedDatabaseTokenDefaults(
            config=database_token_config,
            backend_name=UNSET if database_token_config is None else database_token_config.backend_name,
        ),
        api_key=ResolvedApiKeyDefaults(
            config=api_key_config,
            enabled=api_key_config.enabled,
            backend_name=api_key_config.backend_name,
            hash_secret=_resolve_api_key_hash_secret(config),
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


def _build_startup_backend_templates[UP: UserProtocol[Any], ID](
    config: LitestarAuthConfig[UP, ID],
    *,
    defaults: ResolvedFeatureDefaults,
) -> tuple[StartupBackendTemplate[UP, ID], ...]:
    startup_backends: tuple[StartupBackendTemplate[UP, ID], ...]
    if defaults.database_token.config is not None:
        from litestar_auth._plugin import database_token as _database_token_module  # noqa: PLC0415

        startup_backends = (
            _database_token_module._build_database_token_backend_template(  # noqa: SLF001
                defaults.database_token.config,
                unsafe_testing=config.unsafe_testing,
            ),
        )
    else:
        startup_backends = tuple(StartupBackendTemplate.from_runtime_backend(backend) for backend in config.backends)

    if defaults.api_key.enabled:
        from litestar_auth._plugin.api_key import build_api_key_backend_template  # noqa: PLC0415

        if not isinstance(defaults.api_key.hash_secret, UnsetType):
            startup_backends = (
                *startup_backends,
                build_api_key_backend_template(
                    defaults.api_key.config,
                    api_key_hash_secret=defaults.api_key.hash_secret,
                    unsafe_testing=config.unsafe_testing,
                ),
            )
    return startup_backends


def _resolve_api_key_hash_secret[UP: UserProtocol[Any], ID](
    config: LitestarAuthConfig[UP, ID],
) -> str | UnsetType:
    if config.user_manager_security is None or config.user_manager_security.api_key_hash_secret is None:
        return UNSET
    return config.user_manager_security.api_key_hash_secret


def _find_backend_by_name[UP: UserProtocol[Any], ID](
    startup_backends: tuple[StartupBackendTemplate[UP, ID], ...],
    backend_name: str,
) -> tuple[int, StartupBackendTemplate[UP, ID]] | None:
    for index, backend in enumerate(startup_backends):
        if backend.name == backend_name:
            return index, backend
    return None
