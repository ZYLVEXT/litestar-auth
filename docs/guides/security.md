# Security model

litestar-auth separates **authentication** (who is the caller?) from **authorization** (are they allowed to do this?).

## Middleware and `request.user`

`LitestarAuthMiddleware` runs early in the stack. It tries each configured `AuthenticationBackend` in order; the first backend that yields a user wins. **Unauthenticated requests do not automatically fail**—`request.user` may be unset or anonymous depending on your Litestar setup.

Use **guards** on routes that require a logged-in user, verified email, active account, superuser access, or flat role membership via `has_any_role(...)` / `has_all_roles(...)`. See [Guards API](../api/guards.md).

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

For flat role membership checks on app-owned routes, use the built-in role
guard factories instead of reaching into `request.user.roles` directly:

```python
from litestar import get

from litestar_auth.guards import has_all_roles, has_any_role


@get("/reports", guards=[has_any_role("admin", "support")])
async def reports() -> dict[str, bool]:
    return {"ok": True}


@get("/billing/export", guards=[has_all_roles("admin", "billing")])
async def billing_export() -> dict[str, bool]:
    return {"ok": True}
```

These guards require an authenticated active user and a `roles` collection
compatible with `RoleCapableUserProtocol`. Both configured roles and runtime
user roles are normalized with the same trim/lowercase/deduplicate semantics as
the persistence and manager layers.

Whether those roles are backed by the bundled `Role` / `UserRole` tables or an equivalent custom
model family, authorization still sees only the normalized flat `roles` contract. These guard
factories are intentionally limited to flat membership checks; they are not a full RBAC framework,
permission matrix, or object-level policy DSL.

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

JWTs include standard time claims (`iat`, `exp`, `nbf`). Revocation uses a **denylist** store; default in-memory storage is suitable for single-process dev only—use a shared store (e.g. Redis) in multi-worker production. The in-memory denylist rejects new revocations under capacity pressure (after pruning expired entries) rather than evicting an existing revoked JTI; size `max_entries` or use Redis if you issue many concurrent revocations. When a new revocation cannot be stored, `destroy_token` raises `TokenError` (HTTP **503** / `TOKEN_PROCESSING_FAILED` on bundled routes); pending-login TOTP verification uses the same fail-closed pattern for recording the spent pending JTI.

## Rate limiting

When `rate_limit_config` is set, sensitive endpoints may return **429** with `Retry-After`. The **in-memory** limiter is only valid for a single process — use `RedisRateLimiter` in clustered deployments (see [Rate limiting API](../api/ratelimit.md)).

## What the library does not provide

- No built-in email sender (use hooks).
- No admin UI or full RBAC. The shipped relational role tables only back flat membership checks.
- No WebAuthn/passkeys out of the box.

Treat those as application responsibilities.

## Related

- [Configuration](../configuration.md) — `csrf_secret`, `allow_legacy_plaintext_tokens`, OAuth encryption key.
- [Exceptions API](../api/exceptions.md) — error types returned to clients.
