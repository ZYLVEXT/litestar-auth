"""Rate-limiting backends for authentication endpoints."""

from __future__ import annotations

from ._config import AuthRateLimitConfig, EndpointRateLimit, RateLimitScope
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
