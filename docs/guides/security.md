# Security model

litestar-auth separates **authentication** (who is the caller?) from **authorization** (are they allowed to do this?).

## Middleware and `request.user`

`LitestarAuthMiddleware` runs early in the stack. It tries each configured `AuthenticationBackend` in order; the first backend that yields a user wins. **Unauthenticated requests do not automatically fail**—`request.user` may be unset or anonymous depending on your Litestar setup.

Use **guards** on routes that require a logged-in user, verified email, active account, or superuser role. See [Guards API](../api/guards.md).

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
