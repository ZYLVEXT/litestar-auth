# Transports

The **`Transport`** protocol defines how credentials move between client and server: reading token material from an incoming request and attaching issued tokens to responses. Implementations decide *where* credentials live on the wire; a paired **strategy** decides how tokens are validated or minted.

**`BearerTransport`** uses the `Authorization: Bearer <token>` header for API-style clients. **`CookieTransport`** stores tokens in HTTP-only cookies for browser sessions, which affects CSRF posture when cookies are used without a separate header secret.

Transports are always composed with a **`Strategy`** inside an **`AuthenticationBackend`**: the backend wires one transport to one strategy so login, logout, and per-request authentication share the same token semantics. For how backends fit together and when to pick Bearer vs cookies, see [Backends: transports and strategies](../concepts/backends.md). For cookie-based setups, review [Cookie transport and CSRF](../cookbook/cookie_csrf.md).

::: litestar_auth.authentication.transport
