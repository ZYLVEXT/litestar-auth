"""Allowlisted reverse-proxy projection of the external HTTPS request target."""

from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING
from urllib.parse import urlsplit

if TYPE_CHECKING:
    from collections.abc import Mapping
    from typing import Any

UNIX_SOCKET_PROXY = "unix"
_DEFAULT_HEADER = b"x-auth-external-target"


@dataclass(frozen=True, slots=True)
class AllowlistedProxyExternalTarget:
    """Project ``target_uri`` only from an allowlisted proxy identity header.

    Client-controlled ``Host`` / ``Forwarded`` are ignored. The proxy must strip
    and re-inject ``x-auth-external-target`` (ADR 0005).
    """

    proxy_addresses: frozenset[str]
    header_name: bytes = _DEFAULT_HEADER

    def __post_init__(self) -> None:
        """Require a non-empty proxy allowlist and header name."""
        if not self.proxy_addresses or not self.header_name:
            msg = "proxy addresses and header name are required"
            raise ValueError(msg)

    def __call__(self, scope: Mapping[str, Any]) -> str | None:
        """Return the absolute HTTPS target or ``None`` when absent.

        Raises:
            ValueError: If the proxy is untrusted or the header is ambiguous/malformed.
        """
        values = _header_values(scope, self.header_name)
        if not values:
            return None
        client_address = _client_address(scope)
        if client_address not in self.proxy_addresses:
            msg = "external request target is not trusted"
            raise ValueError(msg)
        if len(values) != 1:
            msg = "external request target is ambiguous"
            raise ValueError(msg)
        try:
            target = values[0].decode("ascii")
        except UnicodeDecodeError as exc:
            msg = "external request target is invalid"
            raise ValueError(msg) from exc
        _validate_https_target(target)
        return target


def _client_address(scope: Mapping[str, Any]) -> str | None:
    client = scope.get("client")
    if client is None:
        return UNIX_SOCKET_PROXY
    if isinstance(client, tuple) and client and isinstance(client[0], str):
        # Uvicorn/ASGI often reports an empty host for Unix-domain peers.
        return UNIX_SOCKET_PROXY if client[0] in {"", UNIX_SOCKET_PROXY} else client[0]
    return None


def _header_values(scope: Mapping[str, Any], name: bytes) -> list[bytes]:
    wanted = name.lower()
    found: list[bytes] = []
    for raw_name, value in scope.get("headers", ()):
        if raw_name.lower() == wanted:
            found.append(value)
    return found


def _validate_https_target(target: str) -> None:
    parts = urlsplit(target)
    if parts.scheme != "https" or not parts.netloc or parts.fragment or parts.username or parts.password:
        msg = "external request target must be an absolute https URL"
        raise ValueError(msg)


__all__ = ("UNIX_SOCKET_PROXY", "AllowlistedProxyExternalTarget")
