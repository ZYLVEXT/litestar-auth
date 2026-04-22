# Exception Context Reference

`litestar-auth` keeps client-facing HTTP error payloads small and stable, but several domain exceptions now also carry structured context on the exception instance for logging, tracing, and operator diagnostics.

Use the exception attributes for programmatic handling. Do not parse `str(exc)` to recover structured data.

## Serialization boundary

Bundled handlers typically send only the exception message and machine-readable `code` to the client:

```json
{
  "status_code": 400,
  "detail": "Human-readable message",
  "extra": {
    "code": "REGISTER_USER_ALREADY_EXISTS"
  }
}
```

The extra context fields documented below stay on the Python exception object unless your application chooses to expose them.

## `OAuthAccountAlreadyLinkedError`

Raised when an OAuth provider identity is already linked to a different local user.

| Field | Type | Semantics |
| ---- | ---- | --------- |
| `provider` | `str` | Normalized provider name for the conflicting OAuth account, such as `"google"` or `"github"`. |
| `account_id` | `str` | Provider-side account identifier that is already linked. |
| `existing_user_id` | `object` | Local user identifier that already owns that provider identity. |

Notes:
- The constructor stores these context values as provided. If your application needs stricter
  invariants, validate them at the raise site that owns the data.
- The default message includes the three context values for operator-facing diagnostics.

Example catch/log flow:

```python
from logging import getLogger

from litestar_auth.exceptions import OAuthAccountAlreadyLinkedError

logger = getLogger(__name__)

try:
    await user_db.upsert_oauth_account(user, oauth_name="google", account_id="acct-123")
except OAuthAccountAlreadyLinkedError as exc:
    logger.warning(
        "OAuth account conflict provider=%s account_id=%s existing_user_id=%s",
        exc.provider,
        exc.account_id,
        exc.existing_user_id,
    )
    raise
```

Typical bundled-controller response shape:

```json
{
  "status_code": 400,
  "detail": "OAuth account google:acct-123 is already linked to user 42",
  "extra": {
    "code": "OAUTH_ACCOUNT_ALREADY_LINKED"
  }
}
```

## `UserAlreadyExistsError`

Raised when a create or update flow collides with an existing user identity.

| Field | Type | Semantics |
| ---- | ---- | --------- |
| `identifier` | `UserIdentifier | None` | Structured duplicate-identifier payload when supplied. |
| `identifier_type` | `"email" | "username" | None` | Convenience mirror of `identifier.identifier_type`; message-only construction leaves this as `None`. |
| `identifier_value` | `str | None` | Convenience mirror of `identifier.identifier_value`; message-only construction leaves this as `None`. |

Notes:
- Construct with `UserAlreadyExistsError(identifier=UserIdentifier(...))` or omit `identifier`.
- `message`, `code`, and `identifier` are keyword-only.
- Structured construction stores the supplied identifier context as-is.
- The default message includes the identifier context when it is supplied.

Example catch/log flow:

```python
from logging import getLogger

from litestar_auth.exceptions import UserAlreadyExistsError, UserIdentifier

logger = getLogger(__name__)

try:
    raise UserAlreadyExistsError(
        identifier=UserIdentifier(
            identifier_type="email",
            identifier_value="admin@example.com",
        ),
    )
except UserAlreadyExistsError as exc:
    logger.info(
        "Duplicate user identifier_type=%s identifier_value=%r",
        exc.identifier_type,
        exc.identifier_value,
    )
    raise
```

Typical bundled-controller response shape:

```json
{
  "status_code": 400,
  "detail": "A user with the provided credentials already exists.",
  "extra": {
    "code": "REGISTER_USER_ALREADY_EXISTS"
  }
}
```

If your code raises the structured form directly, the default detail changes with the stored context:

```json
{
  "status_code": 400,
  "detail": "User with email='admin@example.com' already exists",
  "extra": {
    "code": "REGISTER_USER_ALREADY_EXISTS"
  }
}
```

## `InvalidPasswordError`

Raised when password validation or verification fails.

| Field | Type | Semantics |
| ---- | ---- | --------- |
| `user_id` | `object | None` | Optional operator-only identifier for the user whose password check failed. |

Notes:
- `message`, `code`, and `user_id` are keyword-only.
- `user_id` is intentionally not included in the default message.
- Use this field for internal logging or security monitoring; do not echo it to untrusted clients unless you have explicitly decided to expose it.

Example catch/log flow:

```python
from logging import getLogger

from litestar_auth.exceptions import InvalidPasswordError

logger = getLogger(__name__)

try:
    await user_manager.update(update, user)
except InvalidPasswordError as exc:
    logger.warning("Password validation failed user_id=%s", exc.user_id)
    raise
```

Typical bundled-controller response shape:

```json
{
  "status_code": 400,
  "detail": "The provided password is invalid.",
  "extra": {
    "code": "UPDATE_USER_INVALID_PASSWORD"
  }
}
```

## `InsufficientRolesError`

Raised when an authenticated user fails a structured role requirement.

| Field | Type | Semantics |
| ---- | ---- | --------- |
| `required_roles` | `frozenset[str]` | Normalized roles required by the authorization check. |
| `user_roles` | `frozenset[str]` | Normalized roles available on the authenticated user. |
| `require_all` | `bool` | `True` when every role in `required_roles` must be present; `False` when any one role is sufficient. |

Notes:
- The constructor stores the supplied role sets as-is; validate role-name invariants at the raise
  site if your application requires them.
- The default message is intentionally generic so ordinary logs and HTTP responses do not leak
  internal role names.
- The built-in role guards raise this exception directly, and the bundled plugin exception wiring
  maps it to HTTP `403` with `code` only by default. Custom exception hooks can still inspect
  `required_roles`, `user_roles`, and `require_all` on the exception instance when operator-facing
  diagnostics need that detail.

Example catch/log flow:

```python
from logging import getLogger

from litestar_auth.exceptions import ErrorCode, InsufficientRolesError

logger = getLogger(__name__)

try:
    raise InsufficientRolesError(
        required_roles=frozenset({"admin", "billing"}),
        user_roles=frozenset({"support"}),
        require_all=True,
    )
except InsufficientRolesError as exc:
    logger.info(
        "Role denial require_all=%s required_roles=%s user_roles=%s",
        exc.require_all,
        sorted(exc.required_roles),
        sorted(exc.user_roles),
    )
    raise
```

Example custom-handler response shape:

```json
{
  "status_code": 403,
  "detail": "The authenticated user does not have all of the required roles.",
  "extra": {
    "code": "INSUFFICIENT_ROLES"
  }
}
```

## Related references

- [Errors reference](errors.md) for the stable `ErrorCode` catalog and typical HTTP mappings.
- [Python API: exceptions](api/exceptions.md) for the full exception hierarchy and signatures.
