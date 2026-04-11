# Security model

litestar-auth separates **authentication** (who is the caller?) from **authorization** (are they allowed to do this?).

## Middleware and `request.user`

`LitestarAuthMiddleware` runs early in the stack. It tries each configured `AuthenticationBackend` in order; the first backend that yields a user wins. **Unauthenticated requests do not automatically fail**—`request.user` may be unset or anonymous depending on your Litestar setup.

Use **guards** on routes that require a logged-in user, verified email, active account, or superuser role. See [Guards API](../api/guards.md).

## Protecting app-owned routes

When your application defines its own Litestar handlers outside the plugin-owned route table, use both:

- `guards=[is_authenticated]` (or `is_verified`, `is_superuser`, etc.) for runtime enforcement.
- `security=config.resolve_openapi_security_requirements()` for OpenAPI / Swagger metadata.

```python
from litestar import Router, get

from litestar_auth.guards import is_authenticated
from litestar_auth.plugin import LitestarAuthConfig

auth_config = LitestarAuthConfig(...)
auth_security = auth_config.resolve_openapi_security_requirements()


@get("/me", guards=[is_authenticated], security=auth_security)
async def me() -> dict[str, bool]:
    return {"ok": True}


protected_api = Router(
    path="/api",
    guards=[is_authenticated],
    security=auth_security,
    route_handlers=[me],
)
```

With the default `include_openapi_security=True`, the plugin also registers the corresponding security schemes globally, so application-defined routes can reuse the same requirements without hard-coding backend names.

If you intentionally disable plugin-managed OpenAPI security, register `auth_config.resolve_openapi_security_schemes()` yourself in `OpenAPIConfig.components` before using those requirements.

## Transport and strategy

- **Transport** — how credentials travel (Authorization header vs HTTP-only cookies).
- **Strategy** — how tokens are issued, validated, rotated, and revoked.

Compose them with `AuthenticationBackend`. This keeps cookie CSRF concerns and JWT claim validation independent.

## Cookie authentication and CSRF

`CookieTransport` defaults toward browser-safe settings (`httponly`, `secure`, `SameSite=Lax`). For local development you may disable `secure`.

When any cookie transport is present, the plugin configures Litestar **CSRF** if `csrf_secret` is set. State-changing methods must include the expected CSRF header (`csrf_header_name`, default `X-CSRF-Token`). **Set `csrf_secret` in production** whenever you use cookie-based sessions.

## JWT

JWTs include standard time claims (`iat`, `exp`, `nbf`). Revocation uses a **denylist** store; default in-memory storage is suitable for single-process dev only—use a shared store (e.g. Redis) in multi-worker production.

## Rate limiting

When `rate_limit_config` is set, sensitive endpoints may return **429** with `Retry-After`. The **in-memory** limiter is only valid for a single process — use `RedisRateLimiter` in clustered deployments (see [Rate limiting API](../api/ratelimit.md)).

## What the library does not provide

- No built-in email sender (use hooks).
- No admin UI or full RBAC.
- No WebAuthn/passkeys out of the box.

Treat those as application responsibilities.

## Related

- [Configuration](../configuration.md) — `csrf_secret`, `allow_legacy_plaintext_tokens`, OAuth encryption key.
- [Exceptions API](../api/exceptions.md) — error types returned to clients.
