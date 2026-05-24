"""Compatibility exports for auth rate-limit internals."""

from __future__ import annotations

from litestar_auth._optional_deps import _require_redis_asyncio
from litestar_auth._schema_fields import EMAIL_MAX_LENGTH

from ._client_host import (
    _DEFAULT_TRUSTED_HEADERS,
    _client_host,
    _usable_trusted_header_value,
    _warn_missing_proxy_headers_once,
    _warned_missing_proxy_headers,
    logger,
)
from ._identifier_extraction import (
    _API_KEY_HMAC_SCHEME,
    _API_KEY_ID_LENGTH,
    _bounded_identity,
    _extract_api_key_id,
    _extract_api_key_token,
    _extract_email,
    _has_hmac_api_key_authorization,
)
from ._key_derivation import DEFAULT_KEY_PREFIX, _bounded_hash_part, _safe_key_part
from ._validation import RedisScriptResult, SlidingWindow, _validate_configuration

__all__ = (
    "DEFAULT_KEY_PREFIX",
    "EMAIL_MAX_LENGTH",
    "_API_KEY_HMAC_SCHEME",
    "_API_KEY_ID_LENGTH",
    "_DEFAULT_TRUSTED_HEADERS",
    "RedisScriptResult",
    "SlidingWindow",
    "_bounded_hash_part",
    "_bounded_identity",
    "_client_host",
    "_extract_api_key_id",
    "_extract_api_key_token",
    "_extract_email",
    "_has_hmac_api_key_authorization",
    "_load_redis_asyncio",
    "_safe_key_part",
    "_usable_trusted_header_value",
    "_validate_configuration",
    "_warn_missing_proxy_headers_once",
    "_warned_missing_proxy_headers",
    "logger",
)


def _load_redis_asyncio() -> object:
    """Load ``redis.asyncio`` for the Redis rate limiter.

    Returns:
        The imported ``redis.asyncio`` module.
    """
    return _require_redis_asyncio(feature_name="RedisRateLimiter")
