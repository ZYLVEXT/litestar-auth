# Migration Guide

## API-key persistence table

API-key storage now has a dedicated `api_key` table. Import the bundled model from
`litestar_auth.models` or `litestar_auth.models.api_key`; do not import ORM models from the
package root or `litestar_auth.db`. The SQLAlchemy store lives at
`litestar_auth.db.sqlalchemy.SQLAlchemyApiKeyStore`, while the structural store protocol is
available as `litestar_auth.db.BaseApiKeyStore`.

Minimum migration shape for deployments using the bundled model:

```sql
CREATE TABLE api_key (
    id UUID PRIMARY KEY,
    key_id VARCHAR(64) NOT NULL,
    user_id UUID NOT NULL REFERENCES "user" (id),
    hashed_secret BYTEA NOT NULL,
    encrypted_secret BYTEA NULL,
    name VARCHAR(255) NOT NULL,
    scopes JSON NOT NULL,
    prefix_env VARCHAR(32) NOT NULL,
    signing_required BOOLEAN NOT NULL,
    expires_at TIMESTAMP WITH TIME ZONE NULL,
    last_used_at TIMESTAMP WITH TIME ZONE NULL,
    created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT CURRENT_TIMESTAMP,
    revoked_at TIMESTAMP WITH TIME ZONE NULL,
    created_via VARCHAR(64) NOT NULL,
    client_metadata JSON NULL
);

CREATE UNIQUE INDEX ix_api_key_key_id ON api_key (key_id);
CREATE INDEX ix_api_key_user_id ON api_key (user_id);
```

SQLAlchemy metadata equivalent for a hand-written migration:

```python
import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects.postgresql import JSONB, UUID


def upgrade() -> None:
    op.create_table(
        "api_key",
        sa.Column("id", UUID(as_uuid=True), primary_key=True),
        sa.Column("key_id", sa.String(length=64), nullable=False),
        sa.Column("user_id", UUID(as_uuid=True), sa.ForeignKey("user.id"), nullable=False),
        sa.Column("hashed_secret", sa.LargeBinary(), nullable=False),
        sa.Column("encrypted_secret", sa.LargeBinary(), nullable=True),
        sa.Column("name", sa.String(length=255), nullable=False),
        sa.Column("scopes", JSONB(), nullable=False),
        sa.Column("prefix_env", sa.String(length=32), nullable=False),
        sa.Column("signing_required", sa.Boolean(), nullable=False),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("last_used_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("revoked_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("created_via", sa.String(length=64), nullable=False),
        sa.Column("client_metadata", JSONB(), nullable=True),
    )
    op.create_index("ix_api_key_key_id", "api_key", ["key_id"], unique=True)
    op.create_index("ix_api_key_user_id", "api_key", ["user_id"])
```

`key_id` is the public lookup identifier and must stay unique. `hashed_secret` stores only the
keyed secret digest as bytes; raw API-key secrets are not persisted. `encrypted_secret` is nullable
and reserved for signing-mode keys, so non-signing rows should leave it `NULL`. Signing-mode rows
store `fernet:v1:<keyring-key-id>:<ciphertext>` bytes encrypted with
`api_keys.secret_encryption_keyring`; existing bearer keys cannot be upgraded to signing mode
because their raw secret was intentionally never persisted. Create replacement signing-required
keys and revoke the old bearer keys during migration. `client_metadata` must use the same bounded
shape as refresh-session metadata: 1-64 character keys and 1-255 character string values.

### API-key signing-secret Fernet rotation

Deployments that enable request signing must treat `api_keys.secret_encryption_keyring` as an
operator-rotated Fernet keyring. Rotation is a staged data migration, not an automatic library
service:

1. Add the new Fernet key id to the keyring while keeping the old id configured.
2. Deploy the same key map with `active_key_id` changed to the new id.
3. Scan API-key rows where `signing_required = true` and `encrypted_secret IS NOT NULL`.
4. For each candidate, call `BaseUserManager.api_key_signing_secret_requires_reencrypt(row)` and
   then `await BaseUserManager.reencrypt_api_key_signing_secret(row_or_key_id)` when it returns
   `True`.
5. Repeat the scan and remove the retired key id only after no signing-required row still requires
   re-encryption.

The helper accepts a loaded row or a public `key_id`; it rejects raw bearer credentials and never
returns plaintext signing secrets. Bearer rows, missing `encrypted_secret` values, malformed Fernet
envelopes, unknown key ids, and lost replacement rows are fail-closed migration errors. Resolve them
explicitly instead of skipping them in a bulk job.

The library does not add built-in batching, advisory locks, audit-log storage, per-key audit tables,
service-account-only keys, IP allowlists, or mTLS binding for this migration. Keep those concerns in
application-owned migration and observability tooling when your deployment needs them.

## Argon2-only default password helper

The library default password-helper policy is now Argon2-only. `PasswordHelper.from_defaults()`,
bare `PasswordHelper()`, `BaseUserManager(..., password_helper=None)`, and
`LitestarAuthConfig.resolve_password_helper()` all use that default.

Unsupported stored password hashes now fail closed under that policy: verification returns `False`
and `verify_and_update()` does not emit a replacement hash for an unsupported stored value.

Before upgrading a deployment that still depends on unsupported stored password hashes:

1. Re-hash or reset those credentials out of band while the previous release is still serving
   traffic.
2. Confirm the persisted hashes now match your intended Argon2 policy.
3. Deploy the new release only after those credentials no longer depend on unsupported formats.

## Self-service password rotation endpoint

Self-service profile updates and password rotation are now separate contracts. `UserUpdate`
no longer includes `password`, and requests that try to set `password` on the self-service
profile update path are rejected with `REQUEST_BODY_INVALID`.

Update clients that let authenticated users change their own password to call
`POST /users/me/change-password` with `ChangePasswordRequest`:

<!-- litestar-auth:change-password-request -->
```json
{
  "current_password": "current-password",
  "new_password": "new-secure-password"
}
```

Wrong current passwords return the login-shaped `LOGIN_BAD_CREDENTIALS` contract. Invalid
replacement passwords return `UPDATE_USER_INVALID_PASSWORD`. Admin-initiated password rotation
continues through `AdminUserUpdate` on the privileged users update path.

## Self-service `UserUpdate` is email-only

The built-in self-service profile-update schema no longer accepts `is_active`, `is_verified`, or
`roles`. Privileged fields live exclusively on `AdminUserUpdate` for the privileged
`PATCH /users/{id}` route, and self-service requests that include them are rejected at msgspec
decode (`forbid_unknown_fields=True`) before the controller's runtime deny-list ever runs. This
closes a defense-in-depth gap where a regression in the runtime deny-list could silently turn
self-update into a privilege change.

Update clients accordingly:

- Self-service `PATCH /users/me` now accepts only `{ "email": "new@example.com" }`. Send
  privileged updates through admin `PATCH /users/{user_id}` with `AdminUserUpdate` instead.
- Programmatic callers that constructed `UserUpdate(is_active=...)`, `UserUpdate(roles=...)`, or
  similar must switch to `AdminUserUpdate(...)` plus `manager.update(..., allow_privileged=True)`.
- The library's bundled soft-delete path on the privileged `DELETE /users/{user_id}` route was
  migrated to `AdminUserUpdate(is_active=False)` in this release; no application changes needed
  for the built-in users controller.

If you previously customised `user_update_schema=...` to add app-specific safe fields, you can
keep doing that — the runtime `_build_safe_self_update` deny-list still rejects the privileged
field names as defense-in-depth for custom schemas. The change here only narrows the **library
default**.

## Superuser boolean to role membership

Superuser status is now derived from role membership. The public
`is_superuser` guard still exists, but it checks whether `user.roles` contains
the configured `superuser_role_name` (default `"superuser"`) instead of reading
`user.is_superuser`.

Before upgrading a database that still has an `is_superuser` column, preserve
the data by backfilling role membership for every true row:

1. Ensure the role catalog contains the configured superuser role.
2. Insert missing `user_role` association rows for users where
   `user.is_superuser = true`.
3. Deploy code that no longer reads, writes, or serializes `user.is_superuser`.
4. Drop the old `is_superuser` column after verifying those users authenticate
   with the expected role membership.

Example SQL shape for the default role name:

```sql
INSERT INTO role (name, description)
VALUES ('superuser', 'Superuser access')
ON CONFLICT (name) DO NOTHING;

INSERT INTO user_role (user_id, role_name)
SELECT id, 'superuser'
FROM "user"
WHERE is_superuser = true
ON CONFLICT DO NOTHING;
```

Adjust table names, quoting, and conflict handling for your database dialect
and custom model family. Applications using a custom
`LitestarAuthConfig.superuser_role_name` should backfill that normalized role
name instead of `"superuser"`.

Code changes to make at the same time:

- Remove `is_superuser` from custom SQLAlchemy user models and DTOs.
- Stop passing `is_superuser` to `BaseUserManager.create(...)`,
  `BaseUserManager.update(...)`, `/auth/register`, and `/users/*` payloads.
  The generated register and users request schemas now reject undeclared keys
  during request decoding with `ErrorCode.REQUEST_BODY_INVALID`, so stale
  clients surface immediately instead of being silently accepted.
- Grant or revoke superuser access by mutating the normalized `roles`
  collection through an admin path, seed script, migration, or the role-admin
  CLI/controller.

## Custom password-hash column mapping

Custom SQLAlchemy user models should keep `hashed_password` as the runtime
attribute consumed by managers, stores, and token fingerprinting.

When the only customization is the SQL column name, set
`UserModelMixin.auth_hashed_password_column_name = "password_hash"` on the
app-owned user model. Existing app models that already declare
`hashed_password = mapped_column(...)` directly remain valid when the
application intentionally owns that mapped attribute shape; no auth-layer
behavior change is required either way.

## Typing: UP bound narrowing and direct config construction

The typing-only API was tightened so downstream annotations describe the same
runtime contracts the library already expects. Runtime behavior is unchanged,
but type checkers may now surface code that relied on broad `Any`-based bounds,
helper-based config construction, manual generic parameters, or plain `str`
dependency keys.

### `LitestarAuthConfig.create()` to direct construction

Construct `LitestarAuthConfig` directly. The dataclass now owns the full public
configuration surface without separate wrapper helpers.

Before:

```python
from uuid import UUID

from litestar_auth import LitestarAuthConfig

config = LitestarAuthConfig.create(
    user_model=User,
    user_manager_class=UserManager,
    session_maker=session_maker,
)
```

After:

```python
from uuid import UUID

from litestar_auth import LitestarAuthConfig

config = LitestarAuthConfig[User, UUID](
    user_model=User,
    user_manager_class=UserManager,
    session_maker=session_maker,
)
```

### `UP bound=UserProtocol[Any]` consumer code

The library's public `UP` type variable is now bounded to `UserProtocol` instead
of `UserProtocol[Any]`. Code that mirrors the old broad bound can usually drop
the `Any` parameter, or can bind the user and ID together with Python 3.12
generic parameter syntax when the ID type matters.

Before:

```python
from typing import Any, TypeVar

from litestar_auth.types import UserProtocol

UP = TypeVar("UP", bound=UserProtocol[Any])


def user_id(user: UP) -> object:
    return user.id
```

After:

```python
from typing import TypeVar

from litestar_auth.types import UserProtocol

UP = TypeVar("UP", bound=UserProtocol)


def user_id[ID](user: UserProtocol[ID]) -> ID:
    return user.id
```

Use `UserProtocol` as the broad runtime-checkable user bound. Use
`UserProtocol[ID]` when the function or class needs to preserve the concrete ID
type through its return values or collaborators.

### TOTP user-model validation moves to startup

Apps with `totp_config` enabled must use a `user_model` that exposes the
`TotpUserProtocol` fields: `email` and `totp_secret`. The plugin now checks that
contract during startup, so a misconfigured app fails before routes are mounted.
Previously, the same misconfiguration could surface only after a login reached
the pending-2FA branch.

### TOTP recovery-code lookup index migration

TOTP recovery-code storage changed from `recovery_codes_hashes: list[str]` to
`recovery_codes: dict[str, str]`. The dict maps a server-side HMAC-SHA-256
lookup digest to the Argon2 hash for that one recovery code, so verification
performs one dictionary lookup and one Argon2 verify instead of checking every
active hash.

Migration steps:

1. Add a distinct CSPRNG-generated
   `UserManagerSecurity.totp_recovery_code_lookup_secret` that clears the production secret-strength gate.
2. Run your application migration to remove or null `recovery_codes_hashes` and
   add nullable JSON `recovery_codes`.
3. Deploy the library/application change.
4. Notify TOTP users that existing recovery codes no longer work; they should
   authenticate with their TOTP app and regenerate codes through
   `/auth/2fa/recovery-codes/regenerate`.

### `DbSessionDependencyKey` adoption

Annotate custom DB-session dependency keys with `DbSessionDependencyKey` instead
of plain `str`. This keeps application code aligned with
`LitestarAuthConfig.db_session_dependency_key` and documents the Python
identifier constraint at the call site.

Before:

```python
from litestar_auth import LitestarAuthConfig

db_session_dependency_key: str = "db_session"

config = LitestarAuthConfig[User, UUID](
    user_model=User,
    user_manager_class=UserManager,
    session_maker=session_maker,
    db_session_dependency_key=db_session_dependency_key,
)
```

After:

```python
from litestar_auth import LitestarAuthConfig
from litestar_auth.types import DbSessionDependencyKey

db_session_dependency_key: DbSessionDependencyKey = "db_session"

config = LitestarAuthConfig[User, UUID](
    user_model=User,
    user_manager_class=UserManager,
    session_maker=session_maker,
    db_session_dependency_key=db_session_dependency_key,
)
```

### String rate-limit slot keys to `AuthRateLimitSlot`

These snippets use `InMemoryRateLimiter` only to show the slot-key migration in a
small single-process/dev/test setup. For production multi-worker deployments,
use `RedisRateLimiter` or `RedisAuthPreset` and declare the topology with
`LitestarAuthConfig.deployment_worker_count`.

Before:

```python
from litestar_auth.ratelimit import AuthRateLimitConfig, EndpointRateLimit, InMemoryRateLimiter

config = AuthRateLimitConfig.from_shared_backend(
    backend=InMemoryRateLimiter(max_attempts=5, window_seconds=60),
    endpoint_overrides={
        "totp_verify": EndpointRateLimit(
            backend=InMemoryRateLimiter(max_attempts=3, window_seconds=60),
            scope="ip",
            namespace="totp-verify",
        ),
    },
)
```

After:

```python
from litestar_auth.ratelimit import (
    AuthRateLimitConfig,
    AuthRateLimitSlot,
    EndpointRateLimit,
    InMemoryRateLimiter,
    SharedRateLimitConfigOptions,
)

config = AuthRateLimitConfig.from_shared_backend(
    backend=InMemoryRateLimiter(max_attempts=5, window_seconds=60),
    options=SharedRateLimitConfigOptions(
        endpoint_overrides={
            AuthRateLimitSlot.TOTP_VERIFY: EndpointRateLimit(
                backend=InMemoryRateLimiter(max_attempts=3, window_seconds=60),
                scope="ip",
                namespace="totp-verify",
            ),
        },
    ),
)
```

`AuthRateLimitSlot` keeps override mappings typed, IDE-friendly, and aligned
with the preferred public surface.
