# Rate limiting

`AuthRateLimitConfig.from_shared_backend()` is the canonical public entrypoint for the common shared-backend recipe. It materializes endpoint-specific `EndpointRateLimit` values from the package-owned auth slot catalog while keeping manual `AuthRateLimitConfig(..., EndpointRateLimit(...))` assembly available as the advanced escape hatch.

::: litestar_auth.ratelimit
    options:
      members:
        - AuthRateLimitConfig
        - EndpointRateLimit
        - RateLimitScope
        - InMemoryRateLimiter
        - RedisRateLimiter
        - RateLimiterBackend
        - TotpRateLimitOrchestrator
        - TotpSensitiveEndpoint
