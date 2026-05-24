"""Request-facing security validation for plugin configuration."""

from __future__ import annotations

import warnings
from typing import TYPE_CHECKING, Any, cast

from litestar_auth._plugin.middleware import get_cookie_transports
from litestar_auth._plugin.rate_limit import iter_rate_limit_endpoints
from litestar_auth._plugin.validation._core import format_configuration_message
from litestar_auth.config import MINIMUM_SECRET_LENGTH, resolve_trusted_proxy_setting, validate_production_secret
from litestar_auth.exceptions import ConfigurationError
from litestar_auth.types import UserProtocol

if TYPE_CHECKING:
    from litestar_auth._plugin.config import LitestarAuthConfig


def validate_request_security_config[UP: UserProtocol[Any], ID](config: LitestarAuthConfig[UP, ID]) -> None:
    """Validate request-facing rate-limit and cookie-auth prerequisites."""
    validate_rate_limit_config(config.rate_limit_config)
    validate_cookie_auth_config(config)


def validate_backend_security_config[UP: UserProtocol[Any], ID](config: LitestarAuthConfig[UP, ID]) -> None:
    """Validate backend-strategy security posture for constructor-time setup."""
    _validate_backend_strategy_security(config)


def _validate_backend_strategy_security[UP: UserProtocol[Any], ID](config: LitestarAuthConfig[UP, ID]) -> None:
    """Validate backend strategy security posture for non-test environments."""
    for backend in config.resolve_startup_backends():
        _warn_backend_name_strategy_mismatch(
            backend_name=getattr(backend, "name", None),
            strategy=getattr(backend, "strategy", None),
        )


def _warn_backend_name_strategy_mismatch(*, backend_name: object, strategy: object) -> None:
    """Warn when a backend name implies JWT but the configured strategy is not JWT-backed."""
    from litestar_auth._plugin.validation._general import _current_jwt_strategy_type  # noqa: PLC0415

    if (
        not isinstance(backend_name, str)
        or "jwt" not in backend_name.casefold()
        or isinstance(strategy, _current_jwt_strategy_type())
    ):
        return

    warnings.warn(
        f"AuthenticationBackend name {backend_name!r} suggests JWTStrategy semantics, but the configured "
        f"strategy is {type(strategy).__name__}. Consider a neutral name like 'bearer' or 'database' "
        "to avoid misleading logs and configuration.",
        UserWarning,
        stacklevel=4,
    )


def validate_rate_limit_config(rate_limit_config: object) -> None:
    """Validate rate-limit backend settings (trusted-proxy flags)."""
    if rate_limit_config is None:
        return

    for endpoint_limit in iter_rate_limit_endpoints(cast("Any", rate_limit_config)):
        if endpoint_limit is None:
            continue
        resolve_trusted_proxy_setting(trusted_proxy=endpoint_limit.trusted_proxy)


def validate_cookie_auth_config[UP: UserProtocol[Any], ID](config: LitestarAuthConfig[UP, ID]) -> None:
    """Validate cookie-auth prerequisites for production deployments.

    Raises:
        ConfigurationError: If cookie auth is enabled without a safe CSRF configuration.
    """
    cookie_transports = get_cookie_transports(config.resolve_startup_backends())
    if not cookie_transports:
        return

    if config.csrf_secret is not None:
        validate_production_secret(
            config.csrf_secret,
            label="csrf_secret",
            unsafe_testing=config.unsafe_testing,
            minimum_length=MINIMUM_SECRET_LENGTH,
        )

    unsafe_cookie_transports = [transport for transport in cookie_transports if transport.allow_insecure_cookie_auth]
    if config.csrf_secret is not None or unsafe_cookie_transports or config.unsafe_testing:
        return

    msg = (
        "CookieTransport in production requires csrf_secret. "
        'Generate one with `python -c "from secrets import token_urlsafe; print(token_urlsafe(32))"` '
        "or set allow_insecure_cookie_auth=True only for controlled non-browser scenarios."
    )
    raise ConfigurationError(format_configuration_message(msg))
