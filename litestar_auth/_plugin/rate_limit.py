"""Shared rate-limit endpoint iteration for plugin helpers."""

from __future__ import annotations

from typing import TYPE_CHECKING, Protocol, cast

if TYPE_CHECKING:
    from litestar_auth.ratelimit import EndpointRateLimit


class _RateLimitConfigProtocol(Protocol):
    """Typed surface shared by startup and validation rate-limit helpers."""

    login: EndpointRateLimit | None
    change_password: EndpointRateLimit | None
    refresh: EndpointRateLimit | None
    register: EndpointRateLimit | None
    forgot_password: EndpointRateLimit | None
    reset_password: EndpointRateLimit | None
    totp_enable: EndpointRateLimit | None
    totp_confirm_enable: EndpointRateLimit | None
    totp_verify: EndpointRateLimit | None
    totp_disable: EndpointRateLimit | None
    totp_regenerate_recovery_codes: EndpointRateLimit | None
    verify_token: EndpointRateLimit | None
    request_verify_token: EndpointRateLimit | None


_RATE_LIMIT_ENDPOINT_SLOT_NAMES = (
    "login",
    "change_password",
    "refresh",
    "register",
    "forgot_password",
    "reset_password",
    "totp_enable",
    "totp_confirm_enable",
    "totp_verify",
    "totp_disable",
    "totp_regenerate_recovery_codes",
    "verify_token",
    "request_verify_token",
)


def iter_rate_limit_endpoint_items(
    rate_limit_config: _RateLimitConfigProtocol,
) -> tuple[tuple[str, EndpointRateLimit | None], ...]:
    """Return configured rate-limit endpoint slots with their endpoint configs."""
    return tuple(
        (
            slot_name,
            cast("EndpointRateLimit | None", getattr(rate_limit_config, slot_name)),
        )
        for slot_name in _RATE_LIMIT_ENDPOINT_SLOT_NAMES
    )


def iter_rate_limit_endpoints(
    rate_limit_config: _RateLimitConfigProtocol,
) -> tuple[EndpointRateLimit | None, ...]:
    """Return the endpoint-specific rate-limit configs used by plugin helpers."""
    return tuple(endpoint_limit for _, endpoint_limit in iter_rate_limit_endpoint_items(rate_limit_config))
