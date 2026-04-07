"""Rate-limiting helpers for authentication endpoints.

Use :meth:`AuthRateLimitConfig.from_shared_backend` for direct shared-backend
assembly when one :class:`InMemoryRateLimiter` or :class:`RedisRateLimiter`
should back the standard auth endpoint set. For the higher-level one-client
Redis preset that also builds a :class:`~litestar_auth.totp.RedisUsedTotpCodeStore`,
see :class:`litestar_auth.contrib.redis.RedisAuthPreset`. Keep manual
``AuthRateLimitConfig(...)`` plus ``EndpointRateLimit(...)`` assembly for
advanced cases that need fully custom per-endpoint wiring.

Examples:
    Build the canonical shared-backend recipe::

        from litestar_auth.ratelimit import (
            AUTH_RATE_LIMIT_VERIFICATION_SLOTS,
            AuthRateLimitConfig,
            RedisRateLimiter,
        )

        rate_limit_config = AuthRateLimitConfig.from_shared_backend(
            RedisRateLimiter(redis=redis_client, max_attempts=5, window_seconds=60),
            disabled=AUTH_RATE_LIMIT_VERIFICATION_SLOTS,
        )
"""

from __future__ import annotations

from ._config import (
    AUTH_RATE_LIMIT_ENDPOINT_SLOTS,
    AUTH_RATE_LIMIT_ENDPOINT_SLOTS_BY_GROUP,
    AUTH_RATE_LIMIT_VERIFICATION_SLOTS,
    AuthRateLimitConfig,
    AuthRateLimitEndpointGroup,
    AuthRateLimitEndpointSlot,
    AuthRateLimitNamespaceStyle,
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
    "AUTH_RATE_LIMIT_ENDPOINT_SLOTS",
    "AUTH_RATE_LIMIT_ENDPOINT_SLOTS_BY_GROUP",
    "AUTH_RATE_LIMIT_VERIFICATION_SLOTS",
    "DEFAULT_KEY_PREFIX",
    "_DEFAULT_TRUSTED_HEADERS",
    "AuthRateLimitConfig",
    "AuthRateLimitEndpointGroup",
    "AuthRateLimitEndpointSlot",
    "AuthRateLimitNamespaceStyle",
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
