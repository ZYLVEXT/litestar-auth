# Controllers

HTTP controller factories for advanced wiring. Most applications rely on **`LitestarAuth`** plus `OAuthConfig` for the default plugin-owned OAuth route table instead of mounting these directly.

Use this module when you need direct controller ownership: custom OAuth path prefixes, direct user-manager wiring, or another custom route table.

Import built-in request and response payload types from **`litestar_auth.payloads`**.

::: litestar_auth.controllers
