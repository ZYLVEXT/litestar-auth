"""Redirect-origin validation helpers for plugin and manual OAuth flows."""

from __future__ import annotations

from ipaddress import ip_address

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


def _is_unsafe_redirect_host(host: str) -> bool:
    """Return whether ``host`` is non-routable / SSRF-adjacent for OAuth callbacks.

    Rejects loopback, link-local (incl. RFC 3927 169.254/16 — AWS/GCP IMDS),
    private (RFC 1918), multicast, reserved, and unspecified IP literals so a
    misconfigured ``redirect_base_url`` cannot point provider callbacks at
    internal infrastructure. Hostnames that don't parse as IPs are accepted at
    this layer because reverse-proxy DNS names legitimately resolve to private
    addresses behind NAT; resolution-time enforcement is the operator's job.
    """
    if host.casefold() in _LOOPBACK_HOSTNAMES:
        return True
    try:
        parsed = ip_address(host)
    except ValueError:
        return False
    return (
        parsed.is_loopback
        or parsed.is_link_local
        or parsed.is_private
        or parsed.is_multicast
        or parsed.is_reserved
        or parsed.is_unspecified
    )
