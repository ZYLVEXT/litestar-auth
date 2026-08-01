"""Startup fail-closed requirements for plugin app initialization."""

from __future__ import annotations

from typing import TYPE_CHECKING, Any, cast

from litestar_auth._plugin.oauth_contract import _build_oauth_route_registration_contract
from litestar_auth._plugin.startup._warnings import (
    _collect_process_local_rate_limit_endpoint_names,
    _has_process_local_account_lockout_store,
    _has_process_local_account_token_replay_store,
)
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


def require_shared_account_lockout_store_for_multiworker(config: LitestarAuthConfig[Any, Any]) -> None:
    """Fail closed when declared multi-worker deployments use process-local account lockout state.

    Raises:
        ConfigurationError: If account lockout is enabled with process-local state
            in a known multi-worker deployment.
    """
    if config.unsafe_testing or config.deployment_worker_count is None or config.deployment_worker_count <= 1:
        return
    if not _has_process_local_account_lockout_store(config):
        return

    msg = (
        "Account lockout cannot use a process-local store when deployment_worker_count is greater than 1. "
        "Use RedisAccountLockoutStore for multi-worker deployments."
    )
    raise ConfigurationError(msg)


def require_shared_account_token_replay_store_for_multiworker(config: LitestarAuthConfig[Any, Any]) -> None:
    """Require account-token replay protection and shared multi-worker state.

    Raises:
        ConfigurationError: If replay protection is missing, or if a known
            multi-worker deployment configures a process-local replay store.
    """
    if config.unsafe_testing or (not config.include_verify and not config.include_reset_password):
        return
    if config.account_token_denylist_store is None:
        msg = (
            "Plugin-managed verify/reset routes require an atomic JWTReplayStore. "
            "Configure InMemoryJWTDenylistStore for one process, RedisJWTDenylistStore for distributed "
            "deployments, or disable both account-token routes."
        )
        raise ConfigurationError(msg)
    if config.deployment_worker_count is None or config.deployment_worker_count <= 1:
        return
    if not _has_process_local_account_token_replay_store(config):
        return

    msg = (
        "Verify/reset account-token replay protection must use a shared JWTReplayStore when "
        "deployment_worker_count is greater than 1. Configure RedisJWTDenylistStore or disable "
        "the plugin-managed account-token routes."
    )
    raise ConfigurationError(msg)


def require_shared_totp_stores_for_multiworker(config: LitestarAuthConfig[Any, Any]) -> None:
    """Fail closed when declared multi-worker deployments use process-local TOTP state.

    Raises:
        ConfigurationError: If TOTP is enabled with any process-local state store
            in a known multi-worker deployment.
    """
    totp_config = config.totp_config
    if (
        config.unsafe_testing
        or totp_config is None
        or config.deployment_worker_count is None
        or config.deployment_worker_count <= 1
    ):
        return

    stores = {
        "totp_used_tokens_store": totp_config.totp_used_tokens_store,
        "totp_pending_jti_store": totp_config.totp_pending_jti_store,
        "totp_enrollment_store": totp_config.totp_enrollment_store,
    }
    process_local = [
        name
        for name, store in stores.items()
        if store is not None
        and not bool(
            getattr(
                store,
                "is_shared_across_workers",
                getattr(store, "revocation_is_durable", False),
            ),
        )
    ]
    if not process_local:
        return

    msg = (
        "TOTP state must use shared stores when deployment_worker_count is greater than 1. "
        f"The following stores are process-local: {', '.join(process_local)}. "
        "Use the Redis TOTP and JWT replay stores for multi-worker deployments."
    )
    raise ConfigurationError(msg)


def require_refreshable_strategy_when_enable_refresh(config: LitestarAuthConfig[Any, Any]) -> None:
    """Fail closed when refresh routes are enabled without refresh-capable strategies.

    Raises:
        ConfigurationError: If ``enable_refresh=True`` and any refresh-relevant
            configured backend strategy does not implement ``RefreshableStrategy``.
    """
    if not config.enable_refresh:
        return

    from litestar_auth.authentication.strategy.base import RefreshableStrategy  # ruff: ignore[import-outside-top-level]

    for backend in config.resolve_startup_backends():
        strategy = backend.strategy
        if isinstance(strategy, RefreshableStrategy):
            continue

        msg = (
            f"enable_refresh=True but backend {backend.name!r} uses strategy {type(strategy).__name__}, "
            "which does not implement RefreshableStrategy. Configure a refresh-capable strategy "
            "(DatabaseTokenStrategy or RedisTokenStrategy) "
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
