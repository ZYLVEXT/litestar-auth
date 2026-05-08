"""Redirect-origin validation helpers for plugin and manual OAuth flows."""

from __future__ import annotations

import socket
from ipaddress import ip_address
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from ipaddress import IPv4Address, IPv6Address

_LOOPBACK_HOSTNAMES: frozenset[str] = frozenset({"localhost", "ip6-localhost", "ip6-loopback"})


def _is_loopback_host(host: str) -> bool:
    """Return whether ``host`` is a localhost or loopback IP literal.

    Kept as the narrow predicate for callers that only need the loopback test
    (e.g. the relocated startup contract that still distinguishes loopback
    from other non-public hosts in error wording).
    """
    if host == "localhost":
        return True
    try:
        return ip_address(host).is_loopback
    except ValueError:
        return False


def _ip_is_unsafe(parsed: IPv4Address | IPv6Address) -> bool:
    """Return whether ``parsed`` falls in a non-routable / SSRF-adjacent range.

    Covers loopback, RFC 1918 private, RFC 3927 link-local (incl. AWS/GCP
    IMDS at ``169.254.169.254``), multicast, reserved, and unspecified.
    """
    return (
        parsed.is_loopback
        or parsed.is_link_local
        or parsed.is_private
        or parsed.is_multicast
        or parsed.is_reserved
        or parsed.is_unspecified
    )


def _hostname_resolves_to_unsafe_ip(host: str) -> bool:
    """Return whether DNS resolution of ``host`` yields a non-routable address.

    Resolution is performed once at validation time (controller construction
    or plugin startup), so the cost is paid up front rather than on every
    OAuth callback. Fails open when the platform DNS resolver is unavailable
    (offline CI, sandboxed test environments, or temporary network failures
    during startup) so misconfigured infrastructure does not surface as a
    spurious validation error; runtime egress firewall enforcement remains
    the operator's responsibility for that path. DNS rebinding is not
    defended here either: the address resolved at validation time may differ
    from the address used at runtime, so operators relying on this gate must
    pair it with egress controls.
    """
    try:
        addrinfo_records = socket.getaddrinfo(host, None, type=socket.SOCK_STREAM)
    except socket.gaierror:
        return False
    for *_, sockaddr in addrinfo_records:
        try:
            resolved = ip_address(sockaddr[0])
        except (ValueError, IndexError):
            continue
        if _ip_is_unsafe(resolved):
            return True
    return False


def _is_unsafe_redirect_host(host: str) -> bool:
    """Return whether ``host`` is non-routable / SSRF-adjacent for OAuth callbacks.

    Rejects loopback, link-local (incl. RFC 3927 169.254/16 — AWS/GCP IMDS),
    private (RFC 1918), multicast, reserved, and unspecified IP literals so a
    misconfigured ``redirect_base_url`` cannot point provider callbacks at
    internal infrastructure. Hostnames are additionally checked via DNS at
    validation time so an A/AAAA record pointing at internal addresses is
    caught before the OAuth ``code`` is ever issued; resolution failures
    fall through to the historical accept-hostname behaviour so offline CI
    and sandboxed environments still validate hostnames structurally.
    """
    if host.casefold() in _LOOPBACK_HOSTNAMES:
        return True
    try:
        return _ip_is_unsafe(ip_address(host))
    except ValueError:
        return _hostname_resolves_to_unsafe_ip(host)
