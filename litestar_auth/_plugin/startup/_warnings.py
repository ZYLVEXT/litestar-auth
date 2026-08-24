"""Startup warnings for insecure plugin app initialization defaults."""

from __future__ import annotations

import warnings
from typing import TYPE_CHECKING, Any, cast

from litestar_auth._plugin.middleware import get_cookie_transports
from litestar_auth._plugin.oauth_contract import _build_oauth_route_registration_contract
from litestar_auth._plugin.rate_limit import iter_rate_limit_endpoint_items
from litestar_auth.authentication.strategy._jwt_denylist import (
    InMemoryJWTDenylistStore as CurrentInMemoryJWTDenylistStore,
)
from litestar_auth.exceptions import SecurityWarning
from litestar_auth.ratelimit._config import warn_account_lockout_response_floor_too_low
from litestar_auth.totp import InMemoryTotpEnrollmentStore as CurrentInMemoryTotpEnrollmentStore
from litestar_auth.totp import InMemoryUsedTotpCodeStore as CurrentInMemoryUsedTotpCodeStore

if TYPE_CHECKING:
    from litestar_auth._plugin.config import LitestarAuthConfig


def warn_insecure_plugin_startup_defaults(config: LitestarAuthConfig[Any, Any]) -> None:
    """Emit ``SecurityWarning`` for insecure production defaults.

    Suppressed when ``config.unsafe_testing`` is true. Call from
    ``LitestarAuth.on_app_init()`` before guards that may raise.
    """
    if config.unsafe_testing:
        return

    _warn_plaintext_oauth_token_storage(config)
    _warn_process_local_account_token_replay_store(config)
    _warn_process_local_rate_limit_backend(config)
    _warn_process_local_account_lockout_store(config)
    _warn_account_lockout_response_floor_too_low(config)
    _warn_process_local_totp_stores(config)
    _warn_refresh_cookie_max_age_mismatch(config)


def _account_token_routes_enabled(config: LitestarAuthConfig[Any, Any]) -> bool:
    """Return whether plugin-managed verify or reset routes consume account tokens."""
    return config.include_verify or config.include_reset_password


def _has_process_local_account_token_replay_store(config: LitestarAuthConfig[Any, Any]) -> bool:
    """Return whether enabled account-token routes lack shared replay state."""
    if not _account_token_routes_enabled(config):
        return False
    store = config.account_token_denylist_store
    return store is None or not bool(getattr(store, "revocation_is_durable", False))


def _warn_process_local_account_token_replay_store(config: LitestarAuthConfig[Any, Any]) -> None:
    if not _has_process_local_account_token_replay_store(config):
        return
    warnings.warn(
        "Verify/reset account-token replay protection is process-local or disabled. "
        "Concurrent token use is not coordinated across workers; use RedisJWTDenylistStore "
        "or another shared JWTReplayStore for multi-worker production.",
        SecurityWarning,
        stacklevel=2,
    )


def _warn_plaintext_oauth_token_storage(config: LitestarAuthConfig[Any, Any]) -> None:
    contract = _build_oauth_route_registration_contract(
        auth_path=config.auth_path,
        oauth_config=config.oauth_config,
    )
    oauth_config = config.oauth_config
    if oauth_config is None or not contract.has_configured_providers or oauth_config.has_oauth_token_encryption:
        return
    warnings.warn(
        "OAuth providers are configured but OAuth token encryption key material is not set; "
        "OAuth access and refresh tokens may be stored in plaintext at rest. "
        "Configure a Fernet keyring via oauth_token_encryption_keyring for production.",
        SecurityWarning,
        stacklevel=2,
    )


def _warn_process_local_rate_limit_backend(config: LitestarAuthConfig[Any, Any]) -> None:
    if _has_inmemory_rate_limit_backend(config):
        warnings.warn(
            "Auth rate limiting is configured with a process-local in-memory backend. "
            "Rate-limit state will not be shared across workers in multi-worker deployments. "
            "Use a Redis-backed rate limiter to enforce consistent limits across processes.",
            SecurityWarning,
            stacklevel=2,
        )


def _warn_process_local_account_lockout_store(config: LitestarAuthConfig[Any, Any]) -> None:
    account_lockout_config = config.account_lockout_config
    if not account_lockout_config.enabled or account_lockout_config.resolve_store().is_shared_across_workers:
        return
    warnings.warn(
        "Account lockout is configured with a process-local in-memory store. "
        "Lockout state will not be shared across workers in multi-worker deployments. "
        "Use RedisAccountLockoutStore to enforce consistent account lockouts across processes.",
        SecurityWarning,
        stacklevel=2,
    )


def _warn_account_lockout_response_floor_too_low(config: LitestarAuthConfig[Any, Any]) -> None:
    warn_account_lockout_response_floor_too_low(
        config.account_lockout_config,
        login_minimum_response_seconds=config.login_minimum_response_seconds,
        stacklevel=3,
    )


def _warn_process_local_totp_stores(config: LitestarAuthConfig[Any, Any]) -> None:
    totp_config = config.totp_config
    if totp_config is None:
        return

    if isinstance(totp_config.totp_used_tokens_store, CurrentInMemoryUsedTotpCodeStore):
        warnings.warn(
            "TOTP replay protection uses InMemoryUsedTotpCodeStore; used-code state is not "
            "shared across workers. Use RedisUsedTotpCodeStore for production multi-worker deployments.",
            SecurityWarning,
            stacklevel=2,
        )
    if isinstance(totp_config.totp_enrollment_store, CurrentInMemoryTotpEnrollmentStore):
        warnings.warn(
            "TOTP enrollment state uses InMemoryTotpEnrollmentStore; pending enrollment secrets are not "
            "shared across workers. Use RedisTotpEnrollmentStore for production multi-worker deployments.",
            SecurityWarning,
            stacklevel=2,
        )
    if isinstance(totp_config.totp_pending_jti_store, CurrentInMemoryJWTDenylistStore):
        warnings.warn(
            "TOTP pending-token replay protection uses InMemoryJWTDenylistStore; pending JTI state is not "
            "shared across workers. Use RedisJWTDenylistStore for production multi-worker deployments.",
            SecurityWarning,
            stacklevel=2,
        )


def _has_inmemory_rate_limit_backend(config: LitestarAuthConfig[Any, Any]) -> bool:
    """Return whether any endpoint uses a process-local rate-limit backend."""
    return bool(_collect_process_local_rate_limit_endpoint_names(config))


def _has_process_local_account_lockout_store(config: LitestarAuthConfig[Any, Any]) -> bool:
    """Return whether account lockout uses process-local state."""
    account_lockout_config = config.account_lockout_config
    return account_lockout_config.enabled and not account_lockout_config.resolve_store().is_shared_across_workers


def _collect_process_local_rate_limit_endpoint_names(config: LitestarAuthConfig[Any, Any]) -> tuple[str, ...]:
    """Return configured rate-limit endpoint slots backed by process-local state."""
    rate_limit_config = config.rate_limit_config
    if rate_limit_config is None:
        return ()

    process_local_endpoint_names: list[str] = []
    for endpoint_name, endpoint_limit in iter_rate_limit_endpoint_items(cast("Any", rate_limit_config)):
        if endpoint_limit is None:
            continue
        if not endpoint_limit.backend.is_shared_across_workers:
            process_local_endpoint_names.append(endpoint_name)
    return tuple(process_local_endpoint_names)


def _warn_refresh_cookie_max_age_mismatch(config: LitestarAuthConfig[Any, Any]) -> None:
    """Warn when a CookieTransport will silently inherit ``max_age`` for the refresh cookie.

    When ``enable_refresh`` is true and a ``CookieTransport`` has ``refresh_max_age is None``,
    the refresh cookie inherits the access-token ``max_age`` - which is typically much shorter
    than the strategy's refresh lifetime. The browser will delete the refresh cookie before it
    expires server-side, causing silent refresh failures.
    """
    if not config.enable_refresh:
        return

    cookie_transports = get_cookie_transports(config.resolve_startup_backends())
    for transport in cookie_transports:
        if transport.refresh_max_age is None:
            warnings.warn(
                "CookieTransport refresh_max_age is not set while enable_refresh=True. "
                "The refresh cookie will inherit the access-token max_age, which is typically "
                "much shorter than the strategy's refresh lifetime. Set refresh_max_age explicitly "
                "on CookieTransport to match your strategy's refresh token TTL.",
                SecurityWarning,
                stacklevel=3,
            )
            break
