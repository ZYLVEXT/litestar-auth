"""Shared rate-limit endpoint iteration for plugin helpers."""

from __future__ import annotations

from typing import TYPE_CHECKING, Protocol

if TYPE_CHECKING:
    from litestar_auth.ratelimit import EndpointRateLimit


class _RateLimitConfigProtocol(Protocol):
    """Typed surface shared by startup and validation rate-limit helpers."""

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


def iter_rate_limit_endpoints(
    rate_limit_config: _RateLimitConfigProtocol,
) -> tuple[EndpointRateLimit | None, ...]:
    """Return the endpoint-specific rate-limit configs used by plugin helpers."""
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
