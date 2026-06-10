"""Startup warnings for insecure plugin app initialization defaults."""

from __future__ import annotations

import warnings
from typing import TYPE_CHECKING, Any, cast

from litestar_auth._plugin.middleware import get_cookie_transports
from litestar_auth._plugin.oauth_contract import _build_oauth_route_registration_contract
from litestar_auth._plugin.rate_limit import iter_rate_limit_endpoint_items
from litestar_auth._plugin.security_policy import _describe_jwt_revocation_policy
from litestar_auth.exceptions import SecurityWarning

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
    _warn_jwt_revocation_policy(config)
    _warn_jwt_default_fingerprint_user_model_gap(config)
    _warn_process_local_rate_limit_backend(config)
    _warn_process_local_totp_stores(config)
    _warn_refresh_cookie_max_age_mismatch(config)
    _warn_api_key_unbounded_default_ttl(config)


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


def _user_model_exposes_hashed_password(user_model: type[Any]) -> bool:
    """Return whether the configured user model declares a ``hashed_password`` attribute.

    Walks both class-level attributes (SQLAlchemy column descriptors, dataclass slots,
    explicit assignments) and per-class ``__annotations__`` (msgspec/Pydantic-style
    declarations and ``Protocol`` user contracts) so the check works across the
    persistence and contract shapes the library supports.
    """
    sentinel = object()
    if getattr(user_model, "hashed_password", sentinel) is not sentinel:
        return True
    for cls in getattr(user_model, "__mro__", (user_model,)):
        if "hashed_password" in getattr(cls, "__annotations__", {}):
            return True
    return False


def _warn_jwt_default_fingerprint_user_model_gap(config: LitestarAuthConfig[Any, Any]) -> None:
    """Warn when the default JWT session fingerprint will silently degrade for the user model.

    The default ``session_fingerprint_getter`` requires (id, email, hashed_password)
    on the authenticated user so JWTs implicitly rotate on credential changes.
    Passkey-only or OAuth-only models that omit ``hashed_password`` cause the default
    getter to return ``None`` for every user, disabling the binding without a
    visible signal. This warner converts that silent degradation into a startup
    notice; callers using a custom ``session_fingerprint_getter`` are unaffected.
    """
    if _user_model_exposes_hashed_password(config.user_model):
        return

    for backend in config.resolve_startup_backends():
        strategy = getattr(backend, "strategy", None)
        getter = getattr(strategy, "session_fingerprint_getter", None)
        if getter is None or not getattr(getter, "_is_default_session_fingerprint", False):
            continue
        warnings.warn(
            f"Backend {backend.name!r} uses JWTStrategy with the default session "
            f"fingerprint, but {config.user_model.__name__!r} does not expose "
            "'hashed_password'. JWTs minted by this strategy will not rotate when "
            "credentials change. Provide an explicit session_fingerprint_getter when "
            "using passkey-only or OAuth-only user models.",
            SecurityWarning,
            stacklevel=2,
        )
        return


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


def _warn_api_key_unbounded_default_ttl(config: LitestarAuthConfig[Any, Any]) -> None:
    api_key_config = config.api_keys
    if not api_key_config.enabled or api_key_config.default_ttl is not None:
        return
    warnings.warn(
        "API-key creation default_ttl is None; newly created API keys may be non-expiring unless callers "
        "set an explicit expires_at. Prefer a bounded default_ttl for production.",
        SecurityWarning,
        stacklevel=2,
    )


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
