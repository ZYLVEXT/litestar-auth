# Payloads and Schemas

`litestar_auth.payloads` is the authoritative public boundary for the built-in auth lifecycle DTOs published by the
default controllers. `litestar_auth.schemas` still documents the default user CRUD structs used for registration and
user-facing reads or updates.

`UserEmailField` and `UserPasswordField` are the supported public schema-helper aliases for app-owned
`msgspec.Struct` registration/update schemas. Import them from `litestar_auth.schemas` when you want custom `email`
and `password` fields to keep the same documented regex, max-length, and password-length metadata as the built-in
`UserCreate` and `UserUpdate` structs without copying local constraints. Existing `UserPasswordField` imports remain
supported; add `UserEmailField` when you also want the built-in email contract on app-owned schemas. For the full
contract between schema metadata, `password_validator_factory`, and shared `PasswordHelper` injection, see
[Configuration](../configuration.md#manager-password-surface).

These aliases only describe schema validation and OpenAPI metadata. Runtime password policy still lives on the
manager side through `password_validator_factory` or the manager's default validator.

Schema usage example:

```python
import msgspec

from litestar_auth.schemas import UserEmailField, UserPasswordField


class AppUserCreate(msgspec.Struct, forbid_unknown_fields=True):
    email: UserEmailField
    password: UserPasswordField
```

## Built-in auth payloads

!!! note "Import path"

    Prefer importing built-in request and response structs from ``litestar_auth.payloads``:

    ```python
    from litestar_auth.payloads import LoginCredentials, RefreshTokenRequest
    ```

    The package root (``litestar_auth``) and controllers package (``litestar_auth.controllers``) no longer re-export
    these types. User CRUD schemas also stay in ``litestar_auth.schemas`` instead of passing through this module.
    Import auth lifecycle DTOs from ``litestar_auth.payloads`` so code follows the documented payload boundary.

Use these types when you want the exact request and response structs exposed by the built-in login, refresh, verify,
reset-password, and TOTP routes.

::: litestar_auth.payloads
    options:
      members:
        - LoginCredentials
        - RefreshTokenRequest
        - ForgotPassword
        - ResetPassword
        - RequestVerifyToken
        - VerifyToken
        - TotpEnableRequest
        - TotpEnableResponse
        - TotpVerifyRequest
        - TotpConfirmEnableRequest
        - TotpConfirmEnableResponse
        - TotpDisableRequest

## User CRUD schemas

These remain the default msgspec schemas for registration and user CRUD surfaces. Import `UserCreate`, `UserRead`, and
`UserUpdate` from `litestar_auth.schemas`; neither the package root nor `litestar_auth.payloads` re-exports them.
`UserEmailField` and `UserPasswordField` live here as well and are the supported aliases for sharing the built-in
email/password metadata with app-owned create/update structs while the manager keeps runtime validation for passwords.

::: litestar_auth.schemas
