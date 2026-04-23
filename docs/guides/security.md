# Security model

litestar-auth separates **authentication** (who is the caller?) from **authorization** (are they allowed to do this?).

## Middleware and `request.user`

`LitestarAuthMiddleware` runs early in the stack. It tries each configured `AuthenticationBackend` in order; the first backend that yields a user wins. **Unauthenticated requests do not automatically fail**—`request.user` may be unset or anonymous depending on your Litestar setup.

Use **guards** on routes that require a logged-in user, verified email, active account, superuser access, or flat role membership via `has_any_role(...)` / `has_all_roles(...)`. See [Guards API](../api/guards.md).
`is_superuser` is also role-based: it checks the configured superuser role name
(`"superuser"` by default) against the authenticated user's normalized `roles`.

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

## Object-level authorization

Flat role guards answer "does this caller have a role?", not "does this caller
own this object?". For tenant resources, account-scoped records, invoices,
projects, or admin-on-behalf-of flows, add an application-owned ownership or
policy check after authentication.

```python
from dataclasses import dataclass
from uuid import UUID

from litestar import Request, get
from litestar.exceptions import PermissionDeniedException

from litestar_auth.guards import is_authenticated
from litestar_auth.types import UserProtocol


@dataclass(frozen=True, slots=True)
class Project:
    id: UUID
    owner_id: UUID


async def load_project(project_id: UUID) -> Project:
    ...


@get("/projects/{project_id:uuid}", guards=[is_authenticated])
async def get_project(
    request: Request[UserProtocol[UUID], object, object],
    project_id: UUID,
) -> Project:
    project = await load_project(project_id)
    if project.owner_id != request.user.id:
        raise PermissionDeniedException(detail="You are not allowed to access this resource.")
    return project
```

Keep these checks close to the resource lookup or centralize them in your
service layer. Do not rely on predictable IDs, hidden UI controls, or flat roles
alone for object ownership.

With the default `include_openapi_security=True`, the plugin also registers the corresponding security schemes globally, so application-defined routes can reuse the same requirements without hard-coding backend names.

If you intentionally disable plugin-managed OpenAPI security, register `auth_config.resolve_openapi_security_schemes()` yourself in `OpenAPIConfig.components` before using those requirements.

## Transport and strategy

- **Transport** — how credentials travel (Authorization header vs HTTP-only cookies).
- **Strategy** — how tokens are issued, validated, rotated, and revoked.

Compose them with `AuthenticationBackend`. This keeps cookie CSRF concerns and JWT claim validation independent.

For Redis-backed opaque tokens, `RedisTokenStrategy.invalidate_all_tokens(user)` invalidates tokens
through the per-user Redis index written by current `write_token(...)` calls. It does not perform a
global keyspace scan, so token keys created by older deployments without that index remain valid only
until their Redis TTL expires. Flush or rotate those pre-index keys during an upgrade if immediate
revocation is required.

## Cookie authentication and CSRF

`CookieTransport` defaults toward browser-safe settings (`httponly`, `secure`, `SameSite=Lax`). For local development you may disable `secure`.

When any cookie transport is present, the plugin configures Litestar **CSRF** if `csrf_secret` is set. State-changing methods must include the expected CSRF header (`csrf_header_name`, default `X-CSRF-Token`). **Set `csrf_secret` in production** whenever you use cookie-based sessions.

If you bypass the plugin and mount `create_auth_controller(...)` manually with
`CookieTransport`, declare the CSRF posture at construction time. Pass
`csrf_protection_managed_externally=True` only when your Litestar app already
protects those routes with CSRF middleware or an equivalent framework-level
mechanism. For controlled non-browser cookie flows that intentionally do not use
CSRF, set `CookieTransport(allow_insecure_cookie_auth=True)` explicitly.

## JWT

JWTs include standard time claims (`iat`, `exp`, `nbf`). Access-token validation accepts a small built-in leeway for normal clock skew, so minor NTP drift does not force unnecessary re-authentication at the edge of token lifetime. Revocation uses a **denylist** store; pass a shared store (e.g. Redis) in multi-worker production, or set `allow_inmemory_denylist=True` only for explicit single-process development/test wiring. The in-memory denylist rejects new revocations under capacity pressure (after pruning expired entries) rather than evicting an existing revoked JTI; size `max_entries` or use Redis if you issue many concurrent revocations. When a new revocation cannot be stored, `destroy_token` raises `TokenError` (HTTP **503** / `TOKEN_PROCESSING_FAILED` on bundled routes); pending-login TOTP verification uses the same fail-closed pattern for recording the spent pending JTI.

## Rate limiting

When `rate_limit_config` is set, sensitive endpoints may return **429** with `Retry-After`. The **in-memory** limiter is only valid for a single process — use `RedisRateLimiter` in clustered deployments (see [Rate limiting API](../api/ratelimit.md)).

## What the library does not provide

- No built-in email sender (use hooks).
- No admin UI or full RBAC. The shipped relational role tables only back flat membership checks.
- No WebAuthn/passkeys out of the box.

Treat those as application responsibilities.

## Related

- [Configuration](../configuration.md) — `csrf_secret`, JWT/TOTP downgrade controls, OAuth encryption key.
- [Exceptions API](../api/exceptions.md) — error types returned to clients.
