"""Client-host resolution helpers for auth rate limiting."""

from __future__ import annotations

import ipaddress
import logging
from typing import TYPE_CHECKING

from litestar_auth.config import resolve_trusted_proxy_hops, resolve_trusted_proxy_setting

if TYPE_CHECKING:
    from ._protocol import KnownRateLimitConnection

_DEFAULT_TRUSTED_HEADERS: tuple[str, ...] = ("X-Forwarded-For",)
logger = logging.getLogger("litestar_auth.ratelimit")
_warned_missing_proxy_headers: set[tuple[str, ...]] = set()


def _warn_missing_proxy_headers_once(trusted_headers: tuple[str, ...]) -> None:
    """Warn at most once per process when configured proxy headers are all absent."""
    if trusted_headers in _warned_missing_proxy_headers:
        return

    _warned_missing_proxy_headers.add(trusted_headers)
    logger.warning(
        "trusted_proxy=True but none of the configured trusted headers (count=%d) were present on the request; "
        "rate-limit identity is falling back to the direct client host. Verify the reverse proxy "
        "is actually setting one of these headers, or set trusted_proxy=False.",
        len(trusted_headers),
    )


def _select_x_forwarded_for_trusted_hop(value: str, *, trusted_proxy_hops: int = 1) -> str | None:
    """Return the trusted hop from an X-Forwarded-For header value.

    The rightmost entry is the IP appended by the immediately upstream trusted
    proxy, while the leftmost entries are client-controlled and may be spoofed.
    Trusting the leftmost would let an attacker forge arbitrary identities by
    sending ``X-Forwarded-For: <spoof>`` which the proxy then appends the real
    client IP to (typical ``proxy_add_x_forwarded_for`` behavior).

    Operators with a multi-proxy chain (e.g. CDN -> LB -> app) where the real
    client IP is N hops from the right can configure ``trusted_proxy_hops=N``.
    If the header carries fewer entries than the configured hop count, the
    header is treated as unusable and the caller falls back to the direct client
    host.
    """
    parts = [part.strip() for part in value.split(",") if part.strip()]
    if len(parts) < trusted_proxy_hops:
        return None
    return parts[-trusted_proxy_hops]


def _usable_trusted_header_value(header_name: str, raw_value: str, *, trusted_proxy_hops: int = 1) -> str | None:
    """Return a trusted proxy header value when it carries a usable IP address."""
    value = raw_value.strip()
    if not value:
        return None

    if header_name.lower() == "x-forwarded-for":
        selected_value = _select_x_forwarded_for_trusted_hop(value, trusted_proxy_hops=trusted_proxy_hops)
        if selected_value is None:
            return None
        value = selected_value

    try:
        ipaddress.ip_address(value)
    except ValueError:
        return None
    return value


def _client_host(
    request: KnownRateLimitConnection,
    *,
    trusted_proxy: bool = False,
    trusted_headers: tuple[str, ...] = _DEFAULT_TRUSTED_HEADERS,
    trusted_proxy_hops: int = 1,
) -> str:
    """Return the remote host for a request, or a stable fallback.

    Args:
        request: Incoming HTTP request.
        trusted_proxy: Whether to read client IP from proxy headers.
        trusted_headers: Ordered header names to consult when ``trusted_proxy``
            is ``True``. Only headers your reverse proxy explicitly sets should
            be listed; defaults to ``("X-Forwarded-For",)`` to match common
            single-proxy deployments and avoid trusting provider-specific
            headers the proxy does not control.
        trusted_proxy_hops: Which ``X-Forwarded-For`` entry to trust, counted
            from the right. The default ``1`` preserves the single trusted proxy
            behavior. Fewer header entries than this value fail closed to the
            direct client host.
    """

    def fallback_host() -> str:
        """Return the direct client host, or ``"unknown"`` when Litestar did not expose one."""
        client = request.client
        if client is None or not client.host:
            return "unknown"
        return client.host

    if not resolve_trusted_proxy_setting(trusted_proxy=trusted_proxy):
        return fallback_host()
    resolved_hops = resolve_trusted_proxy_hops(trusted_proxy_hops=trusted_proxy_hops)

    headers = request.headers
    all_headers_absent = True
    for header_name in trusted_headers:
        raw_value = headers.get(header_name) or headers.get(header_name.lower())
        if raw_value is not None:
            all_headers_absent = False
        if not raw_value:
            continue

        if value := _usable_trusted_header_value(
            header_name=header_name,
            raw_value=raw_value,
            trusted_proxy_hops=resolved_hops,
        ):
            return value

    if all_headers_absent:
        _warn_missing_proxy_headers_once(trusted_headers)
    return fallback_host()
