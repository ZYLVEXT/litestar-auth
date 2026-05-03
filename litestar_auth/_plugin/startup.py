"""Startup-only warnings and fail-closed guards for plugin app initialization."""

from __future__ import annotations

import importlib
import warnings
from functools import cache
from typing import TYPE_CHECKING, Any, cast
from urllib.parse import urlsplit

from litestar_auth._plugin._redirect_validation import _is_loopback_host
from litestar_auth._plugin.middleware import get_cookie_transports
from litestar_auth._plugin.oauth_contract import _build_oauth_route_registration_contract
from litestar_auth._plugin.rate_limit import iter_rate_limit_endpoint_items
from litestar_auth._plugin.security_policy import _describe_jwt_revocation_policy
from litestar_auth.exceptions import ConfigurationError
from litestar_auth.totp import SecurityWarning

if TYPE_CHECKING:
    from litestar.config.app import AppConfig

    from litestar_auth._plugin.config import LitestarAuthConfig, OAuthConfig


@cache
def _load_bundled_token_orm_models() -> tuple[object, object]:
    """Load the bundled DB-token ORM classes exactly once per process.

    Returns:
        The bundled access-token and refresh-token ORM classes.
    """
    models_module = importlib.import_module("litestar_auth.models")
    return cast("Any", models_module).import_token_orm_models()


def bootstrap_bundled_token_orm_models(config: LitestarAuthConfig[Any, Any]) -> None:
    """Load bundled token ORM models during plugin app init when runtime uses them."""
    from litestar_auth._plugin.database_token import (  # noqa: PLC0415
        _uses_bundled_database_token_models,
    )

    if _uses_bundled_database_token_models(config):
        _load_bundled_token_orm_models()


def warn_insecure_plugin_startup_defaults(config: LitestarAuthConfig[Any, Any]) -> None:
    """Emit ``SecurityWarning`` for insecure production defaults.

    Suppressed when ``config.unsafe_testing`` is true. Call from
    ``LitestarAuth.on_app_init()`` before guards that may raise.
    """
    if config.unsafe_testing:
        return

    _warn_plaintext_oauth_token_storage(config)
    _warn_jwt_revocation_policy(config)
    _warn_process_local_rate_limit_backend(config)
    _warn_process_local_totp_stores(config)
    _warn_refresh_cookie_max_age_mismatch(config)


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


def _warn_jwt_revocation_policy(config: LitestarAuthConfig[Any, Any]) -> None:
    for backend in config.resolve_startup_backends():
        strategy = getattr(backend, "strategy", None)
        notice = _describe_jwt_revocation_policy(getattr(strategy, "revocation_posture", None))
        warning_message = None if notice is None else notice.startup_warning
        if isinstance(warning_message, str):
            warnings.warn(
                warning_message,
                SecurityWarning,
                stacklevel=2,
            )
            break


def _warn_process_local_rate_limit_backend(config: LitestarAuthConfig[Any, Any]) -> None:
    if _has_inmemory_rate_limit_backend(config):
        warnings.warn(
            "Auth rate limiting is configured with a process-local in-memory backend. "
            "Rate-limit state will not be shared across workers in multi-worker deployments. "
            "Use a Redis-backed rate limiter to enforce consistent limits across processes.",
            SecurityWarning,
            stacklevel=2,
        )


def _warn_process_local_totp_stores(config: LitestarAuthConfig[Any, Any]) -> None:
    totp_config = config.totp_config
    if totp_config is None:
        return

    from litestar_auth.authentication.strategy.jwt import (  # noqa: PLC0415
        InMemoryJWTDenylistStore as CurrentInMemoryJWTDenylistStore,
    )
    from litestar_auth.totp import (  # noqa: PLC0415
        InMemoryTotpEnrollmentStore as CurrentInMemoryTotpEnrollmentStore,
    )
    from litestar_auth.totp import (  # noqa: PLC0415
        InMemoryUsedTotpCodeStore as CurrentInMemoryUsedTotpCodeStore,
    )

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

    The lazy per-request check in generated auth controllers remains as defense-in-depth
    for direct controller construction that bypasses plugin startup.

    Raises:
        ConfigurationError: If ``enable_refresh=True`` and any configured backend
            strategy does not implement ``RefreshableStrategy``.
    """
    if not config.enable_refresh:
        return

    from litestar_auth.authentication.strategy.base import RefreshableStrategy  # noqa: PLC0415

    for backend in config.resolve_startup_backends():
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


def require_secure_oauth_redirect_in_production(
    *,
    config: LitestarAuthConfig[Any, Any],
    app_config: AppConfig,
) -> None:
    """Fail closed when plugin-owned OAuth redirects use insecure production origins."""
    if config.unsafe_testing or getattr(app_config, "debug", False):
        return

    contract = _build_oauth_route_registration_contract(
        auth_path=config.auth_path,
        oauth_config=config.oauth_config,
    )
    if not contract.has_plugin_owned_login_routes:
        return
    redirect_base_url = contract.redirect_base_url
    if redirect_base_url is None:  # pragma: no cover - validation guarantees this when providers exist
        return

    parsed_redirect_base_url = urlsplit(redirect_base_url)
    _require_https_oauth_redirect_base_url(redirect_base_url, parsed_redirect_base_url.scheme)
    _require_public_oauth_redirect_host(redirect_base_url, parsed_redirect_base_url.hostname)
    _require_clean_oauth_redirect_base_url(
        redirect_base_url,
        has_userinfo=parsed_redirect_base_url.username is not None or parsed_redirect_base_url.password is not None,
        has_query=bool(parsed_redirect_base_url.query),
        has_fragment=bool(parsed_redirect_base_url.fragment),
    )


def _require_https_oauth_redirect_base_url(redirect_base_url: str, scheme: str) -> None:
    if scheme.lower() == "https":
        return
    msg = (
        "Plugin-managed OAuth routes require oauth_redirect_base_url to use a public HTTPS origin in production. "
        f"Received {redirect_base_url!r}. Use AppConfig(debug=True) or unsafe_testing=True only for explicit "
        "local-development and test recipes."
    )
    raise ConfigurationError(msg)


def _require_public_oauth_redirect_host(redirect_base_url: str, host: str | None) -> None:
    if host is not None and not _is_loopback_host(host):
        return
    msg = (
        "Plugin-managed OAuth routes require oauth_redirect_base_url to use a non-loopback public HTTPS origin "
        f"in production. Received {redirect_base_url!r}. Use AppConfig(debug=True) or unsafe_testing=True only "
        "for explicit local-development and test recipes."
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


def _has_inmemory_rate_limit_backend(config: LitestarAuthConfig[Any, Any]) -> bool:
    """Return whether any endpoint uses a process-local rate-limit backend."""
    return bool(_collect_process_local_rate_limit_endpoint_names(config))


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
