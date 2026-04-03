"""Startup-only warnings and fail-closed guards for plugin app initialization."""

from __future__ import annotations

import logging
import warnings
from typing import TYPE_CHECKING, Any, cast
from urllib.parse import urlsplit

from litestar_auth._plugin.middleware import get_cookie_transports
from litestar_auth._plugin.rate_limit import iter_rate_limit_endpoints
from litestar_auth.authentication.strategy.jwt import JWTStrategy
from litestar_auth.config import is_testing
from litestar_auth.totp import InMemoryUsedTotpCodeStore, SecurityWarning

if TYPE_CHECKING:
    from litestar.config.app import AppConfig

    from litestar_auth._plugin.config import LitestarAuthConfig, OAuthConfig


logger = logging.getLogger("litestar_auth.plugin")


def _is_jwt_strategy_instance(strategy: object) -> bool:
    """Return whether ``strategy`` is a JWT strategy, even across module reloads.

    Tests reload strategy modules to record module-body coverage. After a reload,
    the current ``JWTStrategy`` class object differs from older imports held by
    this module, so a strict ``isinstance()`` check can miss the intended
    strategy type. Matching on the stable module path and class name keeps the
    startup warning logic consistent without broadening it to unrelated classes.
    """
    strategy_type = type(strategy)
    return isinstance(strategy, JWTStrategy) or (
        strategy_type.__name__ == JWTStrategy.__name__
        and strategy_type.__module__ == JWTStrategy.__module__
        and hasattr(strategy, "revocation_is_durable")
    )


def warn_insecure_plugin_startup_defaults(config: LitestarAuthConfig[Any, Any]) -> None:
    """Emit ``SecurityWarning`` for insecure production defaults.

    Suppressed when ``is_testing()`` is true. Call from ``LitestarAuth.on_app_init()``
    before guards that may raise.
    """
    if is_testing():
        return

    oauth_config = config.oauth_config
    if (
        oauth_config is not None
        and has_configured_oauth_providers(config)
        and not oauth_config.oauth_token_encryption_key
    ):
        warnings.warn(
            "OAuth providers are configured but oauth_token_encryption_key is not set; "
            "OAuth access and refresh tokens may be stored in plaintext at rest. "
            "Configure a Fernet key via oauth_token_encryption_key for production.",
            SecurityWarning,
            stacklevel=2,
        )

    for backend in config.backends:
        strategy = getattr(backend, "strategy", None)
        if _is_jwt_strategy_instance(strategy) and not getattr(strategy, "revocation_is_durable", True):
            warnings.warn(
                "JWTStrategy is configured with a process-local in-memory denylist. "
                "Revoked tokens are not visible across workers; use RedisJWTDenylistStore or "
                "allow_nondurable_jwt_revocation=True only with full understanding of the tradeoff.",
                SecurityWarning,
                stacklevel=2,
            )
            break

    if _has_inmemory_rate_limit_backend(config):
        warnings.warn(
            "Auth rate limiting is configured with a process-local in-memory backend. "
            "Rate-limit state will not be shared across workers in multi-worker deployments. "
            "Use a Redis-backed rate limiter to enforce consistent limits across processes.",
            SecurityWarning,
            stacklevel=2,
        )

    totp_config = config.totp_config
    if totp_config is not None and isinstance(totp_config.totp_used_tokens_store, InMemoryUsedTotpCodeStore):
        warnings.warn(
            "TOTP replay protection uses InMemoryUsedTotpCodeStore; used-code state is not "
            "shared across workers. Use RedisUsedTotpCodeStore for production multi-worker deployments.",
            SecurityWarning,
            stacklevel=2,
        )
    _warn_refresh_cookie_max_age_mismatch(config)


def require_oauth_token_encryption_for_configured_providers(
    *,
    config: LitestarAuthConfig[Any, Any],
    require_key: object,
) -> None:
    """Fail closed when configured OAuth providers would persist plaintext tokens."""
    if not has_configured_oauth_providers(config):
        return
    cast("Any", require_key)(context="OAuth providers are configured")


def has_configured_oauth_providers(config: LitestarAuthConfig[Any, Any]) -> bool:
    """Return whether this plugin config includes any OAuth provider integration."""
    oauth_config = config.oauth_config
    if oauth_config is None:
        return False
    return has_configured_oauth_providers_for(oauth_config)


def has_configured_oauth_providers_for(oauth_config: OAuthConfig) -> bool:
    """Return whether this OAuth config includes any provider integration."""
    return bool(oauth_config.oauth_associate_providers or oauth_config.oauth_providers)


def warn_if_insecure_oauth_redirect_in_production(
    *,
    config: LitestarAuthConfig[Any, Any],
    app_config: AppConfig,
) -> None:
    """Warn when OAuth associate redirect resolution falls back to localhost in production."""
    if getattr(app_config, "debug", False):
        return

    oauth_config = config.oauth_config
    if oauth_config is None:
        return
    if not (oauth_config.include_oauth_associate and oauth_config.oauth_associate_providers):
        return

    associate_path = f"{config.auth_path.rstrip('/')}/associate"
    redirect_base_url = oauth_config.oauth_associate_redirect_base_url or f"http://localhost{associate_path}"
    host = urlsplit(redirect_base_url).hostname
    if host not in {"localhost", "127.0.0.1", "::1"}:
        return

    logger.warning(
        "Insecure OAuth redirect_base_url detected in production. "
        "The configured OAuth associate redirect base URL resolves to localhost (%s). "
        "Set oauth_associate_redirect_base_url to your public HTTPS origin instead of relying on the "
        "http://localhost fallback.",
        redirect_base_url,
        extra={"event": "oauth_redirect_localhost_default"},
    )


def _has_inmemory_rate_limit_backend(config: LitestarAuthConfig[Any, Any]) -> bool:
    """Return whether any endpoint uses a process-local rate-limit backend."""
    rate_limit_config = config.rate_limit_config
    if rate_limit_config is None:
        return False
    for endpoint_limit in iter_rate_limit_endpoints(cast("Any", rate_limit_config)):
        if endpoint_limit is None:
            continue
        if not endpoint_limit.backend.is_shared_across_workers:
            return True
    return False


def _warn_refresh_cookie_max_age_mismatch(config: LitestarAuthConfig[Any, Any]) -> None:
    """Warn when a CookieTransport will silently inherit ``max_age`` for the refresh cookie.

    When ``enable_refresh`` is true and a ``CookieTransport`` has ``refresh_max_age is None``,
    the refresh cookie inherits the access-token ``max_age`` - which is typically much shorter
    than the strategy's refresh lifetime. The browser will delete the refresh cookie before it
    expires server-side, causing silent refresh failures.
    """
    if not config.enable_refresh:
        return

    cookie_transports = get_cookie_transports(config.backends)
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
