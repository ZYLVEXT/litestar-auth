# Organizations

Organization support gives applications a shared identity shape for multi-tenant user membership, a
request-scope current-organization context, and organization-aware role-derived authorization. When
enabled, it can add a JWT active-organization claim and switch-organization route for JWT-capable
auth backends, plus opt-in organization administration surfaces for operators. It does not add
automatic data isolation for application tables.

The model is a global `User` plus organization membership rows:

- `organization` stores the tenant catalog row with a normalized unique `slug` and display `name`.
- `organization_membership` links one global user to one organization and stores normalized
  organization-scoped role names for that membership.

Flat global user roles still exist on the user. Organization membership roles are stored on the
membership row and become the effective role source for permission resolution when a verified
current-organization context is present. Superuser derivation remains global: a user holding the
configured `superuser_role_name` resolves to the `"*"` permission grant even inside an organization.

## `OrganizationConfig`

Organizations are disabled by default. Enable them by setting
`LitestarAuthConfig.organization_config` with an `OrganizationConfig` that provides a store factory.
Startup validation is fail-closed: an enabled organization config without a callable
`store_factory` raises `ConfigurationError`.

```python
from sqlalchemy.ext.asyncio import AsyncSession

from litestar_auth import LitestarAuthConfig, OrganizationConfig
from litestar_auth.db.sqlalchemy import SQLAlchemyOrganizationStore
from litestar_auth.models import Organization, OrganizationInvitation, OrganizationMembership, User


def create_organization_store(session: AsyncSession) -> SQLAlchemyOrganizationStore:
    return SQLAlchemyOrganizationStore(
        session,
        organization_model=Organization,
        membership_model=OrganizationMembership,
        invitation_model=OrganizationInvitation,
    )


config = LitestarAuthConfig(
    user_model=User,
    organization_config=OrganizationConfig(
        enabled=True,
        store_factory=create_organization_store,
        include_switch_organization=True,
        tenant_header_name="X-Organization",
        role_precedence="replace",
        require_authorization_context=False,
    ),
)
```

`OrganizationConfig` currently has these fields:

| Field | Default | Behavior |
| ----- | ------- | -------- |
| `enabled` | `False` | Keeps the organization feature inert unless explicitly enabled. |
| `store_factory` | `None` | Callable receiving the request `AsyncSession` and returning a `BaseOrganizationStore`. Required when `enabled=True`. |
| `include_switch_organization` | `False` | Mounts opt-in `POST /auth/switch-organization` controllers for JWT-capable, non-API-key backends and makes the default tenant resolver trust the signed JWT organization claim. Requires `enabled=True`. |
| `include_organization_admin` | `False` | Mounts the opt-in `/organizations` HTTP controller and registers the plugin-owned `litestar organizations` CLI group. Requires `enabled=True` and `store_factory`. |
| `include_organization_invitations` | `False` | Mounts authenticated invitee-facing `{auth}/organization-invitations/accept` and `{auth}/organization-invitations/decline` routes. Requires `enabled=True`, `store_factory`, and `user_manager_security.organization_invitation_token_secret`. |
| `slug_min_length` | Project default | Lower bound validated at startup; must be greater than zero. |
| `slug_max_length` | Project default | Upper bound validated at startup; must be greater than or equal to `slug_min_length`. |
| `tenant_header_name` | `"X-Organization"` | Header name used when the default header resolver is created. Blank names are rejected when `enabled=True`. |
| `tenant_resolver` | `ClaimTenantResolver()` when `include_switch_organization=True`; otherwise `HeaderTenantResolver(header_name=tenant_header_name)` | Callable that resolves a normalized organization slug from the request, or `None` when no tenant hint is available. Claim-based resolution uses verified JWT auth context; header/subdomain resolution is only an untrusted hint. |
| `role_precedence` | `"replace"` | Permission-resolution policy inside verified organization context. `"replace"` uses only membership roles; `"merge"` combines global user roles and membership roles. The global superuser role still grants `"*"`. |
| `require_authorization_context` | `False` | When `True`, role-derived permission resolution returns no non-superuser permissions unless the request has verified organization context. |

The config does not register an authentication backend or application-table filter. It validates the
persistence seam, registers the current-organization dependency, configures role-derived permission
resolution, and lets authentication middleware publish a verified request context for applications
that opt in.

## Tenant Resolution

Tenant resolvers translate request data into an organization slug. Header and subdomain resolvers are
untrusted tenant hints. `ClaimTenantResolver` is the trusted resolver for JWT organization
activation because it reads only the verified `JWTContext` stored on the request scope after JWT
signature, audience, expiry, revocation, subject, and fingerprint checks have succeeded.

After authentication succeeds, the middleware:

1. calls the configured `tenant_resolver`;
2. looks up the organization by slug through the configured store;
3. looks up a membership row for the authenticated user's `id` and that organization's `id`;
4. publishes current-organization context only when both organization and membership exist.

If any step fails, no current-organization context is published. Anonymous requests do not perform
organization-store lookups. A resolved header, subdomain, or signed claim still becomes current
organization context only after store lookup and membership verification.

`TenantResolver` is the callable protocol:

```python
from typing import Any, Protocol

from litestar.connection import ASGIConnection


class TenantResolver(Protocol):
    def __call__(self, connection: ASGIConnection[Any, Any, Any, Any]) -> str | None: ...
```

The bundled resolvers are:

```python
from litestar_auth import ClaimTenantResolver, HeaderTenantResolver, SubdomainTenantResolver

claim_resolver = ClaimTenantResolver()
header_resolver = HeaderTenantResolver(header_name="X-Organization")
subdomain_resolver = SubdomainTenantResolver(root_domain="example.com")
```

`ClaimTenantResolver` reads `request.auth` only when it is `JWTContext` and returns the normalized
signed `org` claim. Non-JWT strategies, missing JWT context, absent claims, and malformed claims
resolve to `None`. When `include_switch_organization=True` and you do not pass `tenant_resolver`,
this is the default resolver. It is preferred over header or subdomain resolvers because clients
cannot select an active organization just by sending a request header or choosing a host name; they
must first obtain an organization-bound JWT through the membership-verified switch route.

`HeaderTenantResolver` reads one request header case-insensitively and normalizes the value with the
same trim/lowercase slug rules used by `OrganizationMixin`. Blank or invalid values resolve to
`None`.

`SubdomainTenantResolver` reads the request host, strips ports, normalizes IDNA/case, and returns the
subdomain portion for hosts under `root_domain`. The bare root domain, malformed hosts, IPv6
literals, and unrelated domains resolve to `None`.

## Current Organization Dependency

The plugin registers the `litestar_auth_current_organization` dependency. It returns the verified
`CurrentOrganizationContext` for the request, or `None` when no authenticated membership was
verified.

```python
from typing import Any

from litestar import get


@get("/organization/profile")
async def organization_profile(
    litestar_auth_current_organization: Any | None,
) -> dict[str, str | None]:
    organization = getattr(litestar_auth_current_organization, "organization", None)
    return {"organization_id": None if organization is None else str(organization.id)}
```

Use the dependency for reading the verified context in handlers. Use
`requires_organization_membership` when a route must fail closed unless that context exists.

## Signed JWT Active Organization

`JWTStrategy` can issue access tokens with a signed active-organization claim. Ordinary
`write_token(user)` calls stay organization-free. The dedicated issuance seam is
`write_token_for_organization(user, organization)`, which normalizes and signs the organization slug
into the JWT `org` claim:

```python
from typing import Any

from litestar_auth.authentication.strategy.jwt import JWTStrategy


async def issue_active_organization_token(jwt_strategy: JWTStrategy[Any, Any], user: Any) -> str:
    return await jwt_strategy.write_token_for_organization(user, "acme")
```

Callers must verify membership before invoking `write_token_for_organization()`. The strategy signs
the claim but does not query organization storage itself. During authentication,
`JWTStrategy.read_token_with_context()` returns `JWTAuthenticationResult` with
`JWTContext(organization=...)` populated only from a fully verified JWT payload. Missing or malformed
`org` claims are ignored and do not fail otherwise valid JWT authentication.

The plugin-owned switch route is the built-in path that performs that membership check before
issuing an org-bound token.

## Switch Organization Route

Set `OrganizationConfig.include_switch_organization=True` to mount `POST /auth/switch-organization`
for the primary JWT-capable backend. Additional JWT-capable backends mount the same route under
`/auth/{backend_name}/switch-organization`. The controller is not mounted for API-key transports or
strategies that cannot issue organization-bound tokens.

```json
{
  "organization_slug": "acme"
}
```

The route requires an authenticated user. It normalizes and validates `organization_slug`, looks up
the organization by slug, verifies that the authenticated user's `id` has a membership row for the
organization, then calls `write_token_for_organization()` and returns the configured transport's
normal login-token response. For bearer JWT deployments this is a new bearer token response; for
cookie JWT deployments it sets the configured login cookie.

Failures are fail closed and non-enumerating. Invalid slugs, unknown organizations, missing user ids,
missing organization ids, and absent memberships all return `403` with
`ORGANIZATION_SWITCH_DENIED`. Malformed request bodies use `REQUEST_BODY_INVALID`. A successful
switch token can then drive `ClaimTenantResolver` on later requests, and the middleware still
re-verifies organization membership before publishing `litestar_auth_current_organization`.

The switch route is rate-limitable through `AuthRateLimitConfig.organization_switch`. It defaults to
`None`, so enabling `OrganizationConfig.include_switch_organization=True` does not add throttling
unless the application supplies that endpoint limit.

Non-JWT strategies do not gain a signed active organization. Database-token, Redis-token, and
API-key deployments continue to use the untrusted-hint resolver path, such as header or subdomain
tenant hints followed by store lookup and membership verification.

## Organization Invitation Routes

Set `OrganizationConfig.include_organization_invitations=True` to mount authenticated invitee-facing
invitation routes under `auth_path`. These routes use the same organization-invitation JWT and
token-hash-only persistence model used by the admin invitation operations.

`POST /auth/organization-invitations/accept` accepts:

```json
{
  "token": "signed-invitation-token"
}
```

The route validates the signed token and pending invitation row, normalizes `request.user.email`,
requires it to match the stored invitation email, consumes the invitation row, and creates the
organization membership with the stored invitation roles. A consumed, revoked, expired, unknown, or
malformed token fails closed. A valid token presented by a different authenticated email fails with
`ORGANIZATION_INVITATION_EMAIL_MISMATCH`.

`POST /auth/organization-invitations/decline` accepts the same payload, applies the same token and
email ownership checks, and revokes the invitation without creating a membership. The invitation
routes are rate-limitable through `AuthRateLimitConfig.organization_invitation_accept` and
`AuthRateLimitConfig.organization_invitation_decline`.

## Administration

Set `OrganizationConfig(enabled=True, include_organization_admin=True, store_factory=...)` to enable
operator administration surfaces over the shared organization-admin operations layer.

The operations layer is `SQLAlchemyOrganizationAdmin` from
`litestar_auth._plugin.organization_admin`. It wraps the configured `BaseOrganizationStore` and
centralizes these invariants for both HTTP and CLI callers:

- organization slugs are normalized before create/update and slug collisions fail closed with
  `OrganizationAlreadyExistsError`;
- unknown organizations and memberships raise organization-admin lookup exceptions instead of
  returning partial success;
- membership role replacement uses the same role normalization as the rest of the auth surface;
- removing a member or replacing roles may not remove an organization's final privileged member.

By default, privileged organization roles are `owner` and `admin`. The final privileged-member rule
means the last membership holding either role cannot be removed and cannot be demoted to a role set
without `owner` or `admin`. This protects operators from locking themselves out of an organization.

The plugin mounts an opt-in `/organizations` HTTP controller for superusers by default. The default
guard list is `[is_superuser]`; pass explicit guards to
`create_organization_admin_controller(...)` only when the application has an equivalent operator
authorization policy. Organization create and user-scoped organization listing additionally require
global superuser authority in depth, so org-scoped guards cannot satisfy those catalog routes. The
controller exposes organization create/read/update/delete, user-scoped
organization listing, membership add/remove/list, membership role replacement, and invitation
invite/list/revoke operations. Organization create/update payloads reject unknown fields and bound
both `slug` and `name` to `1..128` characters; the slug bound matches the built-in
switch-organization request contract. Organization, membership, and invitation failures are mapped
to stable error codes. Invitation responses include only invitation metadata; the raw invitation
token is sent only to `BaseUserManager.on_after_organization_invitation(invitation, token)` for
out-of-band delivery and is never echoed in HTTP responses.

```python
from litestar_auth.contrib.organization_admin import create_organization_admin_controller
from litestar_auth.guards import is_superuser

OrganizationAdminController = create_organization_admin_controller(
    config=config,
    route_prefix="organizations",
    guards=[is_superuser],
)
```

The same flag registers the `litestar organizations` CLI group when the active Litestar CLI does not
already define an `organizations` command. CLI use also requires `LitestarAuthConfig.session_maker`;
the group opens a configured DB session, builds the configured organization store, and delegates
mutations through the shared admin operations layer:

```bash
litestar organizations create --slug acme --name "Acme"
litestar organizations get <organization_id>
litestar organizations list --user-id <user_id>
litestar organizations update <organization_id> --slug acme-labs --name "Acme Labs"
litestar organizations delete <organization_id>
litestar organizations add-member <organization_id> <user_id> owner
litestar organizations list-members <organization_id>
litestar organizations set-member-roles <organization_id> <user_id> admin
litestar organizations remove-member <organization_id> <user_id>
litestar organizations invite-member <organization_id> invited@example.com member
litestar organizations list-pending-invitations <organization_id>
litestar organizations revoke-invitation <invitation_id>
```

The invitation CLI commands use the same shared operations layer as the HTTP controller. They print
only invitation metadata or a revocation acknowledgement; raw invitation tokens are delivered only
through the configured manager hook.

CLI identifiers are parsed through the configured `id_parser` when present. Misconfigured
organization administration prerequisites and operation failures are surfaced as Click errors instead
of raw tracebacks. The CLI does not duplicate organization mutation rules; it inherits slug
normalization, conflict checks, unknown-target failures, and final privileged-member protection from
the operations layer.

The organization-admin HTTP surface emits these stable `ErrorCode` values:

| Code | Typical HTTP | Emitted when |
| ---- | ------------ | ------------ |
| `ORGANIZATION_ALREADY_EXISTS` | `409` | Creating an organization with an existing normalized slug or updating an organization to another organization's slug. |
| `ORGANIZATION_NOT_FOUND` | `404` | Reading, updating, deleting, listing members for, or adding a member to an unknown organization; malformed organization ids also collapse here. |
| `ORGANIZATION_MEMBERSHIP_ALREADY_EXISTS` | `409` | Adding a membership for a user who is already a member of the organization. |
| `ORGANIZATION_MEMBERSHIP_NOT_FOUND` | `404` | Removing or replacing roles for an unknown membership; malformed user ids also collapse here. |
| `ORGANIZATION_LAST_PRIVILEGED_MEMBER` | `409` | Removing or demoting the final `owner`/`admin` membership in an organization. |
| `ORGANIZATION_INVITATION_INVALID` | `400` | Accepting, declining, or revoking an invitation when the token or row is malformed, unknown, consumed, revoked, or no longer pending. |
| `ORGANIZATION_INVITATION_EXPIRED` | `400` | Accepting or declining an invitation when the signed token or stored pending row has expired. |
| `ORGANIZATION_INVITATION_EMAIL_MISMATCH` | `400` | Accepting or declining an invitation as an authenticated user whose normalized email does not match the stored invitation email. |

## Organization-Scoped Authorization

Organization authorization is based on the verified current-organization context. Tenant hints from a
header or subdomain do not grant roles or permissions until the middleware has resolved the
organization and verified the authenticated user's membership.

General permission guards are organization-aware under that verified context:

- With the default `role_precedence="replace"`, membership roles replace global user roles for
  permission resolution inside the organization.
- With `role_precedence="merge"`, membership roles and global user roles are combined.
- The configured global superuser role is always checked first and still grants `"*"`.
- With `require_authorization_context=True`, non-superuser permission resolution returns no grants
  unless the request has verified organization context.

```python
from litestar import get

from litestar_auth.guards import has_permission


@get("/organization/reports", guards=[has_permission("reports:read")])
async def organization_reports() -> dict[str, bool]:
    return {"ok": True}
```

For routes that should never fall back to global permission semantics, use the explicit
organization-only guards:

```python
from litestar import get

from litestar_auth.guards import has_organization_permission, has_organization_role


@get("/organization/settings", guards=[has_organization_role("owner")])
async def organization_settings() -> dict[str, bool]:
    return {"ok": True}


@get("/organization/members", guards=[has_organization_permission("members:write")])
async def update_organization_members() -> dict[str, bool]:
    return {"ok": True}
```

`has_organization_role()` reads only roles from the verified membership row.
`has_organization_permission()` requires verified organization context before resolving effective
permissions and keeps API-key scope delegation as a ceiling, so an API key cannot exceed the owner
user's organization-scoped grants.

## Models and Import Paths

Reference ORM models are lazy exports from `litestar_auth.models`:

```python
from litestar_auth.models import Organization, OrganizationInvitation, OrganizationMembership
```

The same classes are also available from their concrete module:

```python
from litestar_auth.models.organization import Organization, OrganizationInvitation, OrganizationMembership
```

Do not import these models from `litestar_auth` or `litestar_auth.db`; they are intentionally absent
from those packages. Keeping ORM models out of the root package and the DB contract package preserves
the lazy mapper-registration boundary for applications with custom model registries.

For custom SQLAlchemy model families, compose the side-effect-free mixins instead of inheriting the
reference classes:

```python
from advanced_alchemy.base import DefaultBase

from litestar_auth.models.mixins import OrganizationInvitationMixin, OrganizationMembershipMixin, OrganizationMixin


class Tenant(OrganizationMixin, DefaultBase):
    __tablename__ = "tenant"
    auth_organization_invitation_model = "TenantInvitation"


class TenantMembership(OrganizationMembershipMixin, DefaultBase):
    __tablename__ = "tenant_membership"
    auth_organization_model = "Tenant"
    auth_organization_table = "tenant"


class TenantInvitation(OrganizationInvitationMixin, DefaultBase):
    __tablename__ = "tenant_invitation"
    auth_organization_model = "Tenant"
    auth_organization_table = "tenant"
```

`OrganizationMixin` provides `id`, `slug`, `name`, `created_at`, `updated_at`, and a
`memberships` relationship. Set `auth_organization_invitation_model` on a custom organization class
when it should expose an inverse invitation relationship. `OrganizationMembershipMixin` provides the
`(user_id, organization_id)` membership key, `user` and `organization` relationships, and normalized
`roles: list[str]`. `OrganizationInvitationMixin` stores the normalized `invited_email`, normalized
organization-scoped `roles`, a unique `token_hash`, `expires_at`, `created_at`, and `status`.
Invitation rows never store the raw token.

Invitation tokens are issued through `BaseUserManager.tokens.write_organization_invitation_token()`.
Configure `UserManagerSecurity.organization_invitation_token_secret` before using that helper. It
returns the raw signed token for out-of-band delivery plus `token_hash` and `expires_at` for
`OrganizationInvitationData`; persist only the hash, never the raw token. Validation uses
`BaseUserManager.tokens.validate_organization_invitation_token(token, organization_store=...)` and
checks the JWT signature, `litestar-auth:organization-invitation` audience, token expiry, stored hash
lookup, and row state. Rows must still be `pending` and unexpired; consumed or revoked rows are
rejected. Consumption remains the store's atomic `consume_invitation()` operation, and accept routes
consume before creating membership so a reused token cannot create duplicate memberships.

`SQLAlchemyOrganizationAdmin.invite_member(...)` centralizes invitation creation for organization
administration. It validates and normalizes the target email, normalizes organization-scoped roles,
requires a known organization, issues the token through the manager token helper, stores only the
hash, and returns `OrganizationInvitationIssue(invitation, token)`. The manager fires
`BaseUserManager.on_after_organization_invitation(invitation, token)` exactly once after the row is
created so applications can enqueue email or other out-of-band delivery. The library never sends
mail itself.

The delivery hook is the only plugin-managed place where the raw token leaves the request path. HTTP
and CLI admin responses serialize `OrganizationInvitationRead` metadata (`id`, `organization_id`,
`invited_email`, `roles`, `expires_at`, `status`) and deliberately omit the raw token.

Re-inviting the same normalized email for the same organization supersedes the current unexpired
pending invitation: matching pending rows are revoked before a fresh token and invitation row are
created. This avoids exposing whether the email belongs to an existing account or membership through
different invitation outcomes. Applications that want to suppress delivery for already-handled
recipients should do that in their own delivery pipeline without changing the request-path behavior.
`SQLAlchemyOrganizationAdmin.list_pending_invitations(organization_id, offset=..., limit=...)` returns
unexpired pending rows for a known organization plus the total matching count, and
`revoke_invitation(invitation_id)` marks one pending row revoked or fails closed when the invitation is
unknown or no longer pending.

Use the mixin class hooks when table or relationship names differ:

| Hook | Purpose |
| ---- | ------- |
| `OrganizationMixin.auth_organization_membership_model` | Membership mapper name used by the inverse `memberships` relationship. |
| `OrganizationMixin.auth_organization_membership_relationship_lazy` | Optional SQLAlchemy loader strategy for `memberships`. |
| `OrganizationMembershipMixin.auth_user_model` / `auth_user_table` | Custom user mapper and table target for `user_id`. |
| `OrganizationMembershipMixin.auth_organization_model` / `auth_organization_table` | Custom organization mapper and table target for `organization_id`. |
| `OrganizationMembershipMixin.auth_user_relationship_foreign_keys` / `auth_organization_relationship_foreign_keys` | Toggle explicit `foreign_keys` hints for custom relationship wiring. |
| `OrganizationMembershipMixin.auth_organization_id_ondelete` | Optional `ondelete` behavior for the organization foreign key. |

## Store Contract

The abstract persistence seam lives in `litestar_auth.db`:

```python
from litestar_auth.db import BaseOrganizationStore, MembershipData, OrganizationData, OrganizationInvitationData
```

`BaseOrganizationStore[ORG, MEMBERSHIP, INVITATION, ID]` covers:

- creating, fetching by id, fetching by slug, updating, and deleting organizations;
- adding, fetching, listing, removing, and replacing roles for memberships;
- listing organizations for one user;
- creating, fetching by token hash, listing pending, revoking, and atomically consuming organization invitations.

The membership, user-organization, and pending-invitation list methods accept keyword-only `offset` and
`limit` arguments and return `(items, total)`. `total` is the count of the full filtered set, not the
length of the returned page. Implementations should keep deterministic ordering stable across pages:
memberships by `user_id`, organizations by `slug`, and pending invitations by `invited_email`.

The bundled SQLAlchemy implementation is imported only from the SQLAlchemy adapter boundary:

```python
from litestar_auth.db.sqlalchemy import SQLAlchemyOrganizationStore
```

Construct it with explicit organization and membership models. Invitation methods also require an
explicit invitation model. Omitting a required model is a programming error. Duplicate organization slugs, slug-update collisions, duplicate membership
creation, and unknown-organization membership creation fail closed with `ValueError`. Organization
deletion removes memberships explicitly inside the same transaction before deleting the organization
row. Deletion and membership removal report `False` when no matching row exists.

## Explicit Boundary

Organization-scoped role and role-derived permission authorization, signed JWT active-organization
claims, claim-based tenant resolution, and the opt-in switch-organization route are available. The
library also provides opt-in organization administration HTTP and CLI surfaces. It does not provide
automatic row filtering for application-owned tables. Application tables that carry tenant data must
still enforce their own organization foreign keys, query filters, and database-level isolation
strategy.
