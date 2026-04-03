# Controllers

HTTP controller factories and request/response payload types for advanced wiring. Most applications rely on **`LitestarAuth`** plus the canonical `litestar_auth.oauth.create_provider_oauth_controller(...)` login helper instead of mounting these directly.

Use this module when you need the explicit escape hatch: custom OAuth path prefixes, direct user-manager wiring, or another non-canonical route table.

::: litestar_auth.controllers
