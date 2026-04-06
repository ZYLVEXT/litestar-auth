"""Rate-limiting helpers for authentication endpoints.

Use :meth:`AuthRateLimitConfig.from_shared_backend` for the common case where a
single :class:`InMemoryRateLimiter` or :class:`RedisRateLimiter` should back the
standard auth endpoint set. Keep manual ``AuthRateLimitConfig(...)`` plus
``EndpointRateLimit(...)`` assembly for advanced cases that need fully custom
per-endpoint wiring.

Examples:
    Build the canonical shared-backend recipe::

        from litestar_auth.ratelimit import AuthRateLimitConfig, RedisRateLimiter

        rate_limit_config = AuthRateLimitConfig.from_shared_backend(
            RedisRateLimiter(redis=redis_client, max_attempts=5, window_seconds=60),
        )
"""

from __future__ import annotations

from ._config import (
    AuthRateLimitConfig,
    AuthRateLimitEndpointGroup,
    AuthRateLimitEndpointSlot,
    EndpointRateLimit,
    RateLimitScope,
)
from ._helpers import (
    _DEFAULT_TRUSTED_HEADERS,
    DEFAULT_KEY_PREFIX,
    RedisScriptResult,
    SlidingWindow,
    _client_host,
    _extract_email,
    _load_redis_asyncio,
    _safe_key_part,
    _validate_configuration,
    importlib,
    logger,
)
from ._memory import InMemoryRateLimiter
from ._orchestrator import TotpRateLimitOrchestrator, TotpSensitiveEndpoint
from ._protocol import RateLimiterBackend, RedisClientProtocol, RedisPipelineProtocol
from ._redis import RedisRateLimiter

__all__ = (
    "DEFAULT_KEY_PREFIX",
    "_DEFAULT_TRUSTED_HEADERS",
    "AuthRateLimitConfig",
    "AuthRateLimitEndpointGroup",
    "AuthRateLimitEndpointSlot",
    "EndpointRateLimit",
    "InMemoryRateLimiter",
    "RateLimitScope",
    "RateLimiterBackend",
    "RedisClientProtocol",
    "RedisPipelineProtocol",
    "RedisRateLimiter",
    "RedisScriptResult",
    "SlidingWindow",
    "TotpRateLimitOrchestrator",
    "TotpSensitiveEndpoint",
    "_client_host",
    "_extract_email",
    "_load_redis_asyncio",
    "_safe_key_part",
    "_validate_configuration",
    "importlib",
    "logger",
)
