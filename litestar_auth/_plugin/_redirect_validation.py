"""Redirect-origin validation helpers for plugin startup checks."""

from __future__ import annotations

from ipaddress import ip_address


def _is_loopback_host(host: str) -> bool:
    """Return whether ``host`` is a localhost or loopback IP literal."""
    if host == "localhost":
        return True
    try:
        return ip_address(host).is_loopback
    except ValueError:
        return False
