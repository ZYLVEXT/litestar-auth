# Controllers

HTTP controller factories and request/response payload types for advanced wiring. Most applications rely on **`LitestarAuth`** plus `OAuthConfig` for the default plugin-owned OAuth route table instead of mounting these directly.

Use this module when you need the explicit escape hatch: custom OAuth path prefixes, direct user-manager wiring, or another non-canonical route table.

::: litestar_auth.controllers
