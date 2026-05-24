"""Startup fail-closed requirements for plugin app initialization."""

from __future__ import annotations

from typing import TYPE_CHECKING, Any, cast

from litestar_auth._plugin.oauth_contract import _build_oauth_route_registration_contract
from litestar_auth._plugin.startup._warnings import _collect_process_local_rate_limit_endpoint_names
from litestar_auth.exceptions import ConfigurationError

if TYPE_CHECKING:
    from litestar_auth._plugin.config import LitestarAuthConfig, OAuthConfig


def require_oauth_token_encryption_for_configured_providers(
    *,
    config: LitestarAuthConfig[Any, Any],
    require_key: object,
) -> None:
    """Fail closed when configured OAuth providers would persist plaintext tokens."""
    contract = _build_oauth_route_registration_contract(
        auth_path=config.auth_path,
        oauth_config=config.oauth_config,
    )
    if not contract.has_configured_providers:
        return
    cast("Any", require_key)(context="OAuth providers are configured")


def require_shared_rate_limit_backends_for_multiworker(config: LitestarAuthConfig[Any, Any]) -> None:
    """Fail closed when declared multi-worker deployments use process-local rate limiting.

    Raises:
        ConfigurationError: If a known multi-worker deployment has any configured
            auth rate-limit endpoint backed by process-local state.
    """
    if config.unsafe_testing or config.deployment_worker_count is None or config.deployment_worker_count <= 1:
        return

    process_local_endpoint_names = _collect_process_local_rate_limit_endpoint_names(config)
    if not process_local_endpoint_names:
        return

    formatted_endpoint_names = ", ".join(process_local_endpoint_names)
    msg = (
        "Auth rate limiting cannot use process-local backends when deployment_worker_count is greater than 1. "
        f"The following endpoint slots are not shared across workers: {formatted_endpoint_names}. "
        "Use RedisRateLimiter or RedisAuthPreset for multi-worker deployments."
    )
    raise ConfigurationError(msg)


def require_refreshable_strategy_when_enable_refresh(config: LitestarAuthConfig[Any, Any]) -> None:
    """Fail closed when refresh routes are enabled without refresh-capable strategies.

    API-key backends are intentionally excluded because ``ApiKeyTransport``
    authenticates standalone keys and does not participate in refresh-token flows.
    The lazy per-request check in generated auth controllers remains as defense-in-depth
    for direct controller construction that bypasses plugin startup.

    Raises:
        ConfigurationError: If ``enable_refresh=True`` and any refresh-relevant
            configured backend strategy does not implement ``RefreshableStrategy``.
    """
    if not config.enable_refresh:
        return

    from litestar_auth.authentication.strategy.base import RefreshableStrategy  # noqa: PLC0415
    from litestar_auth.authentication.transport.api_key import ApiKeyTransport  # noqa: PLC0415

    for backend in config.resolve_startup_backends():
        if isinstance(backend.transport, ApiKeyTransport):
            continue

        strategy = backend.strategy
        if isinstance(strategy, RefreshableStrategy):
            continue

        msg = (
            f"enable_refresh=True but backend {backend.name!r} uses strategy {type(strategy).__name__}, "
            "which does not implement RefreshableStrategy. Configure a refresh-capable strategy "
            "(e.g. JWTStrategy with refresh_max_age, DatabaseTokenStrategy, RedisTokenStrategy) "
            "or set enable_refresh=False."
        )
        raise ConfigurationError(msg)


def has_configured_oauth_providers(config: LitestarAuthConfig[Any, Any]) -> bool:
    """Return whether this plugin config includes any OAuth provider integration."""
    return _build_oauth_route_registration_contract(
        auth_path=config.auth_path,
        oauth_config=config.oauth_config,
    ).has_configured_providers


def has_configured_oauth_providers_for(oauth_config: OAuthConfig) -> bool:
    """Return whether this OAuth config includes any provider integration."""
    return bool(oauth_config.oauth_providers)


def _require_https_oauth_redirect_base_url(redirect_base_url: str, scheme: str) -> None:
    if scheme.lower() == "https":
        return
    msg = (
        "Plugin-managed OAuth routes require oauth_redirect_base_url to use a public HTTPS origin in production. "
        f"Received {redirect_base_url!r}. Use AppConfig(debug=True) or unsafe_testing=True only for explicit "
        "local-development and test recipes."
    )
    raise ConfigurationError(msg)


def _require_clean_oauth_redirect_base_url(
    redirect_base_url: str,
    *,
    has_userinfo: bool,
    has_query: bool,
    has_fragment: bool,
) -> None:
    if not has_userinfo and not has_query and not has_fragment:
        return
    msg = (
        "Plugin-managed OAuth routes require oauth_redirect_base_url to be a clean HTTPS callback base without "
        "userinfo, query, or fragment components in production. "
        f"Received {redirect_base_url!r}. Use AppConfig(debug=True) or unsafe_testing=True only for explicit "
        "local-development and test recipes."
    )
    raise ConfigurationError(msg)
