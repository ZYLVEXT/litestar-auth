# Payloads and Schemas

`litestar_auth.payloads` is the authoritative public boundary for the built-in auth lifecycle DTOs published by the
default controllers. `litestar_auth.schemas` still documents the default user CRUD structs used for registration and
user-facing reads or updates.

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
home for their full API reference.

::: litestar_auth.schemas
