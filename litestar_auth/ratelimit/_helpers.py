"""Shared helpers and constants for auth rate limiting."""

from __future__ import annotations

import hashlib
import importlib as _importlib
import ipaddress
import logging
import unicodedata
from collections import deque
from typing import TYPE_CHECKING, Any

from litestar_auth._optional_deps import _require_redis_asyncio
from litestar_auth.config import resolve_trusted_proxy_setting

if TYPE_CHECKING:
    from litestar.connection import Request

type SlidingWindow = deque[float]
type RedisScriptResult = bytes | str | int | float

DEFAULT_KEY_PREFIX = "litestar_auth:ratelimit:"
logger = logging.getLogger("litestar_auth.ratelimit")

importlib = _importlib

_DEFAULT_TRUSTED_HEADERS: tuple[str, ...] = ("X-Forwarded-For",)
_warned_missing_proxy_headers: set[tuple[str, ...]] = set()


def _warn_missing_proxy_headers_once(trusted_headers: tuple[str, ...]) -> None:
    """Warn at most once per process when configured proxy headers are all absent."""
    if trusted_headers in _warned_missing_proxy_headers:
        return

    _warned_missing_proxy_headers.add(trusted_headers)
    logger.warning(
        "trusted_proxy=True but none of the configured headers (%s) were present on the request; "
        "rate-limit identity is falling back to the direct client host. Verify the reverse proxy "
        "is actually setting one of these headers, or set trusted_proxy=False.",
        ", ".join(trusted_headers),
    )


def _usable_trusted_header_value(header_name: str, raw_value: str) -> str | None:
    """Return a trusted proxy header value when it carries a usable host.

    For ``X-Forwarded-For``, take the rightmost entry: that is the IP appended
    by the immediately upstream trusted proxy, while the leftmost entries are
    client-controlled and may be spoofed. Trusting the leftmost would let an
    attacker forge arbitrary identities by sending ``X-Forwarded-For: <spoof>``
    which the proxy then appends the real client IP to (typical
    ``proxy_add_x_forwarded_for`` behavior).

    Operators with a multi-proxy chain (e.g. CDN -> LB -> app) where the real
    client IP is N hops from the right must terminate spoofed XFF at the edge
    proxy or strip the header before this layer.
    """
    value = raw_value.strip()
    if not value:
        return None

    if header_name.lower() == "x-forwarded-for":
        parts = [part.strip() for part in value.split(",") if part.strip()]
        if not parts:
            return None
        value = parts[-1]

    try:
        ipaddress.ip_address(value)
    except ValueError:
        return None
    return value


def _load_redis_asyncio() -> object:
    """Load ``redis.asyncio`` for the Redis rate limiter.

    Returns:
        The imported ``redis.asyncio`` module.
    """
    return _require_redis_asyncio(feature_name="RedisRateLimiter")


def _validate_configuration(*, max_attempts: int, window_seconds: float) -> None:
    """Validate shared rate-limiter settings.

    Raises:
        ValueError: If ``max_attempts`` or ``window_seconds`` is invalid.
    """
    if max_attempts < 1:
        msg = "max_attempts must be at least 1"
        raise ValueError(msg)
    if window_seconds <= 0:
        msg = "window_seconds must be greater than 0"
        raise ValueError(msg)


def _safe_key_part(value: str) -> str:
    """Hash a key component to prevent delimiter injection and collisions.

    Returns:
        Truncated SHA-256 hex digest of the value.
    """
    return hashlib.sha256(value.encode()).hexdigest()[:32]


def _client_host(
    request: Request[Any, Any, Any],
    *,
    trusted_proxy: bool = False,
    trusted_headers: tuple[str, ...] = _DEFAULT_TRUSTED_HEADERS,
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
    """

    def fallback_host() -> str:
        """Return the direct client host, or ``"unknown"`` when Litestar did not expose one."""
        client = request.client
        if client is None or not client.host:
            return "unknown"
        return client.host

    if not resolve_trusted_proxy_setting(trusted_proxy=trusted_proxy):
        return fallback_host()

    headers = request.headers
    all_headers_absent = True
    for header_name in trusted_headers:
        raw_value = headers.get(header_name) or headers.get(header_name.lower())
        if raw_value is not None:
            all_headers_absent = False
        if not raw_value:
            continue

        if value := _usable_trusted_header_value(header_name=header_name, raw_value=raw_value):
            return value

    if all_headers_absent:
        _warn_missing_proxy_headers_once(trusted_headers)
    return fallback_host()


async def _extract_email(
    request: Request[Any, Any, Any],
    *,
    identity_fields: tuple[str, ...] = ("identifier", "username", "email"),
) -> str | None:
    """Best-effort extraction of identifier from a JSON request body.

    Searches through ``identity_fields`` in order, returning the first
    non-empty string value found. Defaults to the login schema's
    ``identifier`` / ``username`` / ``email`` keys.

    Returns:
        The identifier in NFKC + lowercase canonical form so that case and
        Unicode-equivalent variants share a rate-limit bucket with the auth
        lookup performed by ``UserPolicy.normalize_email``. ``None`` when no
        non-empty identifier is found.
    """
    try:
        payload = await request.json()
    except (TypeError, ValueError):
        return None

    if not isinstance(payload, dict):
        return None

    for field_name in identity_fields:
        value = payload.get(field_name)
        if isinstance(value, str) and value.strip():
            return unicodedata.normalize("NFKC", value.strip()).lower()
    return None
