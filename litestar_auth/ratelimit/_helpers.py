"""Shared helpers and constants for auth rate limiting."""

from __future__ import annotations

import hashlib
import importlib as _importlib
import logging
from collections import deque
from functools import partial
from typing import TYPE_CHECKING, Any

from litestar_auth._optional_deps import _require_redis_asyncio
from litestar_auth.config import resolve_trusted_proxy_setting

if TYPE_CHECKING:
    from litestar.connection import Request

type SlidingWindow = deque[float]
type RedisScriptResult = bytes | str | int | float

DEFAULT_KEY_PREFIX = "litestar_auth:ratelimit:"
logger = logging.getLogger("litestar_auth.ratelimit")

_load_redis_asyncio = partial(_require_redis_asyncio, feature_name="RedisRateLimiter")
importlib = _importlib

_DEFAULT_TRUSTED_HEADERS: tuple[str, ...] = ("X-Forwarded-For",)


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
    for header_name in trusted_headers:
        raw_value = headers.get(header_name) or headers.get(header_name.lower())
        if not raw_value:
            continue

        value = raw_value.strip()
        if not value:
            continue

        if header_name.lower() == "x-forwarded-for":
            value = value.split(",", 1)[0].strip()
            if not value:
                continue

        return value

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
        The raw string value when present, otherwise ``None``.
    """
    try:
        payload = await request.json()
    except (TypeError, ValueError):
        return None

    if not isinstance(payload, dict):
        return None

    for field_name in identity_fields:
        value = payload.get(field_name)
        if isinstance(value, str) and value:
            return value
    return None
