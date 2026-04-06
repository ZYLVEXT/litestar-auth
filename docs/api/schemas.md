# Payloads and Schemas

`litestar_auth.payloads` is the authoritative public boundary for the built-in auth lifecycle DTOs published by the
default controllers. `litestar_auth.schemas` still documents the default user CRUD structs used for registration and
user-facing reads or updates.

`UserPasswordField` is the canonical public password-policy reuse surface for app-owned `msgspec.Struct`
registration/update schemas. Import it from `litestar_auth.schemas` when you want custom `password` fields to keep
the same documented length metadata as the built-in `UserCreate` and `UserUpdate` structs without copying numeric
limits:

```python
import msgspec

from litestar_auth.schemas import UserPasswordField


class AppUserCreate(msgspec.Struct):
    email: str
    password: UserPasswordField
```

The alias shares schema metadata only. The default runtime password validator still calls `require_password_length`,
and `password_validator_factory` remains the extension point for additional runtime policy.

## Built-in auth payloads

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

These remain the default msgspec schemas for registration and user CRUD surfaces. `UserCreate`, `UserRead`, and
`UserUpdate` are also re-exported from `litestar_auth.payloads` for compatibility, but this module stays the canonical
home for their full API reference. `UserPasswordField` lives here as well and is the supported alias for sharing the
built-in password-length metadata with app-owned create/update structs.

::: litestar_auth.schemas
