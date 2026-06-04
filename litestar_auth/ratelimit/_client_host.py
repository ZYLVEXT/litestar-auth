"""Client-host resolution helpers for auth rate limiting."""

from __future__ import annotations

import ipaddress
import logging
from typing import TYPE_CHECKING, Protocol

import idna

from litestar_auth.config import resolve_trusted_proxy_hops, resolve_trusted_proxy_setting

if TYPE_CHECKING:
    from collections.abc import Mapping

    from ._protocol import KnownRateLimitConnection

_DEFAULT_TRUSTED_HEADERS: tuple[str, ...] = ("X-Forwarded-For",)
logger = logging.getLogger("litestar_auth.ratelimit")
_warned_missing_proxy_headers: set[tuple[str, ...]] = set()


class _HostHeaderConnection(Protocol):
    """Minimal request-like surface used for host-header parsing."""

    @property
    def headers(self) -> Mapping[str, str]:
        """Return request headers."""


def _get_header_value(headers: Mapping[str, str], header_name: str) -> str | None:
    """Return a header value using case-insensitive matching."""
    value = headers.get(header_name) or headers.get(header_name.lower())
    if value is not None:
        return value

    normalized_name = header_name.casefold()
    for candidate_name, candidate_value in headers.items():
        if candidate_name.casefold() == normalized_name:
            return candidate_value
    return None


def _normalize_host_label(label: str) -> str | None:
    """Return a lowercase Unicode host label, or ``None`` for invalid IDNA."""
    try:
        ascii_label = idna.encode(label, uts46=True)
        return idna.decode(ascii_label, uts46=True).lower()
    except idna.IDNAError:
        return None


def _normalize_host_value(raw_host: str) -> str | None:
    """Return a normalized host name without a port."""
    host = raw_host.strip()
    if not host:
        return None

    if host.startswith("["):
        bracket_index = host.find("]")
        if bracket_index == -1:
            return None
        host = host[1:bracket_index]
    elif host.count(":") == 1:
        host = host.rsplit(":", maxsplit=1)[0]

    labels = [label for label in host.rstrip(".").split(".") if label]
    if not labels:
        return None

    normalized_labels: list[str] = []
    for label in labels:
        normalized_label = _normalize_host_label(label)
        if normalized_label is None:
            return None
        normalized_labels.append(normalized_label)
    return ".".join(normalized_labels)


def _request_host(request: _HostHeaderConnection) -> str | None:
    """Return the normalized HTTP host header without a port."""
    raw_host = _get_header_value(request.headers, "Host")
    if raw_host is None:
        return None
    return _normalize_host_value(raw_host)


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
