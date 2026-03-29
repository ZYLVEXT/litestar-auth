"""Validation and startup checks for the auth plugin façade."""

from __future__ import annotations

import logging
import warnings
from typing import TYPE_CHECKING, Any, Protocol, cast
from urllib.parse import urlsplit

from litestar.config.csrf import CSRFConfig
from sqlalchemy import inspect as sa_inspect

from litestar_auth._plugin.config import (
    DEFAULT_CSRF_COOKIE_NAME,
    LitestarAuthConfig,
    OAuthConfig,
    TotpConfig,
    user_manager_accepts_password_validator,
)
from litestar_auth.authentication.strategy.db import DatabaseTokenStrategy
from litestar_auth.authentication.strategy.jwt import JWTStrategy
from litestar_auth.authentication.transport.cookie import CookieTransport
from litestar_auth.config import (
    MINIMUM_SECRET_LENGTH,
    is_testing,
    resolve_trusted_proxy_setting,
    validate_secret_length,
    validate_testing_mode_for_startup,
)
from litestar_auth.exceptions import ConfigurationError
from litestar_auth.totp import InMemoryUsedTotpCodeStore, SecurityWarning
from litestar_auth.types import UserProtocol

if TYPE_CHECKING:
    from collections.abc import Sequence

    from litestar.config.app import AppConfig

    from litestar_auth.authentication.backend import AuthenticationBackend
    from litestar_auth.ratelimit import EndpointRateLimit


class _RateLimitConfigProtocol(Protocol):
    """Typed surface needed to validate endpoint rate-limit settings."""

    login: EndpointRateLimit | None
    refresh: EndpointRateLimit | None
    register: EndpointRateLimit | None
    forgot_password: EndpointRateLimit | None
    reset_password: EndpointRateLimit | None
    totp_enable: EndpointRateLimit | None
    totp_verify: EndpointRateLimit | None
    totp_disable: EndpointRateLimit | None
    verify_token: EndpointRateLimit | None
    request_verify_token: EndpointRateLimit | None


logger = logging.getLogger("litestar_auth.plugin")


def validate_session_maker_or_external_db_session[UP: UserProtocol[Any], ID](
    config: LitestarAuthConfig[UP, ID],
) -> None:
    """Ensure either a session factory or an external ``db_session`` DI binding exists.

    Raises:
        ValueError: If neither ``session_maker`` nor external session DI is configured.
    """
    has_session_maker = config.session_maker is not None
    has_external_db_session = config.db_session_dependency_provided_externally
    if not has_session_maker and not has_external_db_session:
        msg = (
            "LitestarAuth requires session_maker or db_session_dependency_provided_externally=True "
            f"(inject AsyncSession under dependency key {config.db_session_dependency_key!r})."
        )
        raise ValueError(msg)


def _user_model_defines_login_field(model_cls: object, field_name: str) -> bool:
    """Return whether ``user_model`` exposes ``field_name`` for credential lookup.

    For SQLAlchemy ORM-mapped classes, use :meth:`sqlalchemy.orm.Mapper.has_property`
    so mapped columns, hybrids, and similar mapper properties are recognized. Plain
    dataclasses and other types fall back to :func:`hasattr`.
    """
    mapper = sa_inspect(model_cls, raiseerr=False)
    if mapper is not None and hasattr(mapper, "has_property"):
        return bool(mapper.has_property(field_name))
    return hasattr(model_cls, field_name)


def validate_user_model_login_identifier_fields[UP: UserProtocol[Any], ID](
    config: LitestarAuthConfig[UP, ID],
) -> None:
    """Ensure ``user_model`` defines the attribute implied by ``login_identifier``.

    Raises:
        ConfigurationError: When the model lacks ``email`` or ``username`` as required by
            ``login_identifier``.
    """
    field_name = config.login_identifier
    model_cls = config.user_model
    if not _user_model_defines_login_field(model_cls, field_name):
        msg = (
            f"LitestarAuthConfig.login_identifier is {field_name!r}, but user_model "
            f"{getattr(model_cls, '__name__', model_cls)!r} has no {field_name!r} mapped field or attribute."
        )
        raise ConfigurationError(msg)


def validate_config[UP: UserProtocol[Any], ID](config: LitestarAuthConfig[UP, ID]) -> None:
    """Validate the requested plugin configuration eagerly at startup.

    Raises:
        ValueError: If required plugin, backend, or TOTP settings are invalid.
    """
    validate_testing_mode_for_startup()

    if not config.backends:
        msg = "LitestarAuth requires at least one authentication backend."
        raise ValueError(msg)

    validate_session_maker_or_external_db_session(config)

    validate_password_validator_config(config)
    validate_user_model_login_identifier_fields(config)

    if config.include_users and not callable(getattr(config.user_manager_class, "list_users", None)):
        msg = "include_users=True requires user_manager_class to define list_users()."
        raise ValueError(msg)

    validate_totp_config(config)
    validate_rate_limit_config(config.rate_limit_config)
    validate_cookie_auth_config(config)
    _validate_totp_pending_secret_config(config)
    _validate_backend_strategy_security(config)
    _validate_totp_encryption_key(config)


def _validate_totp_pending_secret_config[UP: UserProtocol[Any], ID](config: LitestarAuthConfig[UP, ID]) -> None:
    """Validate TOTP pending-secret and algorithm constraints.

    Raises:
        ValueError: If TOTP algorithm requirements are not satisfied.
    """
    if config.totp_config is None:
        return
    totp_config = config.totp_config

    validate_secret_length(
        totp_config.totp_pending_secret,
        label="totp_pending_secret",
        minimum_length=MINIMUM_SECRET_LENGTH,
    )
    if not getattr(totp_config, "totp_algorithm", None):
        msg = "totp_algorithm must be configured when totp_config is set."
        raise ValueError(msg)
    if totp_config.totp_algorithm == "SHA1" and not is_testing():
        logger.warning(
            "TOTP is configured with SHA1. For new deployments, consider using SHA256 or SHA512 "
            "if supported by your authenticator clients.",
            extra={"event": "totp_sha1_configured"},
        )


def _validate_backend_strategy_security[UP: UserProtocol[Any], ID](config: LitestarAuthConfig[UP, ID]) -> None:
    """Validate backend strategy security posture for non-test environments."""
    for backend in config.backends:
        strategy = getattr(backend, "strategy", None)
        _validate_database_strategy_legacy_mode(config=config, strategy=strategy)
        if isinstance(strategy, JWTStrategy):
            _validate_jwt_strategy_revocation(config=config, strategy=strategy)
            break


def _validate_database_strategy_legacy_mode[UP: UserProtocol[Any], ID](
    *,
    config: LitestarAuthConfig[UP, ID],
    strategy: object,
) -> None:
    """Validate temporary plaintext-token compatibility mode for DB strategy.

    Raises:
        ValueError: If migration-only plaintext token compatibility is enabled in production.
    """
    if not (
        isinstance(strategy, DatabaseTokenStrategy)
        and strategy.accept_legacy_plaintext_tokens
        and not config.allow_legacy_plaintext_tokens
        and not is_testing()
    ):
        return

    msg = (
        "DatabaseTokenStrategy accept_legacy_plaintext_tokens=True is migration-only and disabled by "
        "default in production. To explicitly accept temporary plaintext-token compatibility during a "
        "controlled rollout, set LitestarAuthConfig.allow_legacy_plaintext_tokens=True and remove it "
        "after rotating sessions and purging legacy rows."
    )
    raise ValueError(msg)


def _validate_jwt_strategy_revocation[UP: UserProtocol[Any], ID](
    *,
    config: LitestarAuthConfig[UP, ID],
    strategy: JWTStrategy[UP, ID],
) -> None:
    """Validate durable revocation requirements for JWT strategy.

    Raises:
        ValueError: If JWT revocation storage is nondurable in production.
    """
    if getattr(strategy, "revocation_is_durable", False) or config.allow_nondurable_jwt_revocation or is_testing():
        return

    msg = (
        "JWTStrategy is configured with a process-local in-memory denylist. "
        "For production deployments, configure a durable denylist store (e.g. RedisJWTDenylistStore) "
        "or use RedisTokenStrategy / DatabaseTokenStrategy. "
        "To explicitly accept nondurable logout semantics, set allow_nondurable_jwt_revocation=True."
    )
    raise ValueError(msg)


def _validate_totp_encryption_key[UP: UserProtocol[Any], ID](config: LitestarAuthConfig[UP, ID]) -> None:
    """Require TOTP secret encryption key in production when TOTP is enabled.

    Raises:
        ConfigurationError: If TOTP is configured but ``totp_secret_key`` is missing
            outside of testing mode.
    """
    if config.totp_config is None or is_testing():
        return
    if not config.user_manager_kwargs.get("totp_secret_key"):
        msg = (
            "totp_secret_key is required in production when TOTP is enabled. "
            "TOTP secrets must be encrypted at rest. Generate a Fernet key with: "
            'python -c "from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())"'
        )
        raise ConfigurationError(msg)


def validate_password_validator_config[UP: UserProtocol[Any], ID](config: LitestarAuthConfig[UP, ID]) -> None:
    """Validate password-validator wiring for the configured user-manager builder.

    Raises:
        ValueError: If explicit and legacy password-validator configuration are mixed, or if an
            explicit password-validator factory targets a manager without a compatible builder.
    """
    if config.password_validator_factory is None:
        return

    if "password_validator" in config.user_manager_kwargs:
        msg = (
            "Configure password validation via password_validator_factory or "
            "user_manager_kwargs['password_validator'], not both."
        )
        raise ValueError(msg)

    if config.user_manager_factory is not None:
        return

    if user_manager_accepts_password_validator(config.user_manager_class):
        return

    msg = (
        "password_validator_factory requires user_manager_class to accept password_validator or "
        "user_manager_factory to build the manager explicitly."
    )
    raise ValueError(msg)


def validate_rate_limit_config(rate_limit_config: object) -> None:
    """Validate rate-limit backend settings (trusted-proxy flags).

    In-memory rate-limit ``SecurityWarning`` emissions happen in
    ``warn_insecure_plugin_startup_defaults`` during ``LitestarAuth.on_app_init``.
    """
    if rate_limit_config is None:
        return

    for endpoint_limit in _iter_rate_limit_endpoints(cast("Any", rate_limit_config)):
        if endpoint_limit is None:
            continue
        resolve_trusted_proxy_setting(trusted_proxy=endpoint_limit.trusted_proxy)


def validate_cookie_auth_config[UP: UserProtocol[Any], ID](config: LitestarAuthConfig[UP, ID]) -> None:
    """Validate cookie-auth prerequisites for production deployments.

    Raises:
        ConfigurationError: If cookie auth is enabled without a safe CSRF configuration.
    """
    cookie_transports = get_cookie_transports(config.backends)
    if not cookie_transports:
        return

    if config.csrf_secret is not None:
        validate_secret_length(
            config.csrf_secret,
            label="csrf_secret",
            minimum_length=MINIMUM_SECRET_LENGTH,
        )

    unsafe_cookie_transports = [transport for transport in cookie_transports if transport.allow_insecure_cookie_auth]
    if config.csrf_secret is not None or unsafe_cookie_transports or is_testing():
        return

    msg = (
        "CookieTransport in production requires csrf_secret. "
        'Generate one with `python -c "from secrets import token_urlsafe; print(token_urlsafe(32))"` '
        "or set allow_insecure_cookie_auth=True only for controlled non-browser scenarios."
    )
    raise ConfigurationError(msg)


def validate_totp_config[UP: UserProtocol[Any], ID](config: LitestarAuthConfig[UP, ID]) -> None:
    """Validate TOTP-specific configuration knobs."""
    if config.totp_config is None:
        return
    validate_totp_sub_config(config.totp_config, user_manager_class=config.user_manager_class)
    if not is_testing():
        cookie_transports = get_cookie_transports(config.backends)
        if cookie_transports and not all(t.secure for t in cookie_transports):
            warnings.warn(
                "TOTP is enabled but CookieTransport.secure=False; TOTP secrets returned by "
                "/2fa/enable may be transmitted over unencrypted connections.",
                SecurityWarning,
                stacklevel=2,
            )


def validate_totp_sub_config[UP: UserProtocol[Any]](
    totp_config: TotpConfig,
    *,
    user_manager_class: type[object],
) -> None:
    """Validate a concrete ``TotpConfig`` payload.

    Raises:
        ValueError: If required TOTP configuration is missing or incompatible.
    """
    if not totp_config.totp_pending_secret:
        msg = "totp_config requires totp_pending_secret."
        raise ValueError(msg)
    if totp_config.totp_require_replay_protection and totp_config.totp_used_tokens_store is None and not is_testing():
        msg = "totp_require_replay_protection=True requires totp_used_tokens_store to be configured."
        raise ValueError(msg)
    if totp_config.totp_enable_requires_password and not callable(
        getattr(user_manager_class, "authenticate", None),
    ):
        msg = (
            "TOTP step-up enrollment is enabled by default. "
            "Configure user_manager_class.authenticate(identifier, password) or set "
            "totp_enable_requires_password=False explicitly (not recommended)."
        )
        raise ValueError(msg)


def _has_inmemory_rate_limit_backend(config: LitestarAuthConfig[Any, Any]) -> bool:
    """Return whether any endpoint uses a process-local rate-limit backend."""
    rate_limit_config = config.rate_limit_config
    if rate_limit_config is None:
        return False
    for endpoint_limit in _iter_rate_limit_endpoints(cast("Any", rate_limit_config)):
        if endpoint_limit is None:
            continue
        if not endpoint_limit.backend.is_shared_across_workers:
            return True
    return False


def warn_insecure_plugin_startup_defaults[UP: UserProtocol[Any], ID](
    config: LitestarAuthConfig[UP, ID],
) -> None:
    """Emit ``SecurityWarning`` for insecure production defaults.

    Suppressed when ``is_testing()`` is true. Call from ``LitestarAuth.on_app_init``
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
        if isinstance(strategy, JWTStrategy) and not strategy.revocation_is_durable:
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


def _warn_refresh_cookie_max_age_mismatch[UP: UserProtocol[Any], ID](
    config: LitestarAuthConfig[UP, ID],
) -> None:
    """Warn when a CookieTransport will silently inherit ``max_age`` for the refresh cookie.

    When ``enable_refresh`` is true and a ``CookieTransport`` has ``refresh_max_age is None``,
    the refresh cookie inherits the access-token ``max_age`` — which is typically much shorter
    than the strategy's refresh lifetime.  The browser will delete the refresh cookie before it
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


def get_cookie_transports[UP: UserProtocol[Any], ID](
    backends: Sequence[AuthenticationBackend[UP, ID]],
) -> list[CookieTransport]:
    """Return configured cookie transports from the backend list."""
    return [
        transport
        for backend in backends
        if isinstance((transport := getattr(backend, "transport", None)), CookieTransport)
    ]


def build_csrf_config[UP: UserProtocol[Any], ID](
    config: LitestarAuthConfig[UP, ID],
    cookie_transports: Sequence[CookieTransport],
) -> CSRFConfig:
    """Build a shared CSRF configuration for homogeneous cookie transports.

    Returns:
        CSRF settings derived from the shared cookie transport configuration.

    Raises:
        ValueError: If cookie transport settings are not homogeneous.
    """
    reference_transport = cookie_transports[0]
    for transport in cookie_transports[1:]:
        if (
            transport.path != reference_transport.path
            or transport.domain != reference_transport.domain
            or transport.secure != reference_transport.secure
            or transport.samesite != reference_transport.samesite
        ):
            msg = (
                "All CookieTransport backends must share path, domain, secure, and samesite settings "
                "to use the plugin-managed CSRF configuration."
            )
            raise ValueError(msg)

    return CSRFConfig(
        secret=cast("str", config.csrf_secret),
        cookie_name=DEFAULT_CSRF_COOKIE_NAME,
        cookie_path=reference_transport.path,
        header_name=config.csrf_header_name,
        cookie_secure=reference_transport.secure,
        cookie_samesite=reference_transport.samesite,
        cookie_domain=reference_transport.domain,
    )


def _iter_rate_limit_endpoints(
    rate_limit_config: _RateLimitConfigProtocol,
) -> tuple[EndpointRateLimit | None, ...]:
    """Return every endpoint-specific rate-limit config for shared validation."""
    return (
        rate_limit_config.login,
        rate_limit_config.refresh,
        rate_limit_config.register,
        rate_limit_config.forgot_password,
        rate_limit_config.reset_password,
        rate_limit_config.totp_enable,
        rate_limit_config.totp_verify,
        rate_limit_config.totp_disable,
        rate_limit_config.verify_token,
        rate_limit_config.request_verify_token,
    )
