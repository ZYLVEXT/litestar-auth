"""Shared rate-limit endpoint iteration for plugin helpers."""

from __future__ import annotations

from typing import TYPE_CHECKING, Protocol, cast

if TYPE_CHECKING:
    from litestar_auth.ratelimit import EndpointRateLimit


class _RateLimitConfigProtocol(Protocol):
    """Typed surface shared by startup and validation rate-limit helpers."""

    @property
    def login(self) -> EndpointRateLimit | None:
        """Configured login endpoint rate limit."""

    @property
    def change_password(self) -> EndpointRateLimit | None:
        """Configured change-password endpoint rate limit."""

    @property
    def refresh(self) -> EndpointRateLimit | None:
        """Configured refresh endpoint rate limit."""

    @property
    def register(self) -> EndpointRateLimit | None:
        """Configured register endpoint rate limit."""

    @property
    def forgot_password(self) -> EndpointRateLimit | None:
        """Configured forgot-password endpoint rate limit."""

    @property
    def reset_password(self) -> EndpointRateLimit | None:
        """Configured reset-password endpoint rate limit."""

    @property
    def totp_enable(self) -> EndpointRateLimit | None:
        """Configured TOTP enable endpoint rate limit."""

    @property
    def totp_confirm_enable(self) -> EndpointRateLimit | None:
        """Configured TOTP confirm-enable endpoint rate limit."""

    @property
    def totp_verify(self) -> EndpointRateLimit | None:
        """Configured TOTP verify endpoint rate limit."""

    @property
    def totp_disable(self) -> EndpointRateLimit | None:
        """Configured TOTP disable endpoint rate limit."""

    @property
    def totp_regenerate_recovery_codes(self) -> EndpointRateLimit | None:
        """Configured TOTP recovery-code regeneration endpoint rate limit."""

    @property
    def verify_token(self) -> EndpointRateLimit | None:
        """Configured verify-token endpoint rate limit."""

    @property
    def request_verify_token(self) -> EndpointRateLimit | None:
        """Configured request-verify-token endpoint rate limit."""

    @property
    def api_key_create(self) -> EndpointRateLimit | None:
        """Configured API-key create endpoint rate limit."""

    @property
    def api_key_update(self) -> EndpointRateLimit | None:
        """Configured API-key update endpoint rate limit."""

    @property
    def api_key_use(self) -> EndpointRateLimit | None:
        """Configured API-key use endpoint rate limit."""


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
    "api_key_create",
    "api_key_update",
    "api_key_use",
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
