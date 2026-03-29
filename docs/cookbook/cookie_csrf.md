# Cookbook: Cookie transport with CSRF

Use `CookieTransport` when you want the access token (or session reference) in an **HttpOnly** cookie instead of `Authorization` headers.

## Requirements

1. Instantiate `CookieTransport` with cookie names and attributes appropriate for your environment (`secure=True` in production behind HTTPS).
2. Set **`csrf_secret`** on `LitestarAuthConfig` so the plugin can build Litestar `CSRFConfig` and, when enabled, register `CSRFMiddleware`.
3. For **unsafe** HTTP methods (POST, PUT, PATCH, DELETE), send the header configured by `csrf_header_name` (default `X-CSRF-Token`) matching the CSRF cookie value.

## Behavior

The plugin detects cookie transports during validation and wires CSRF when configured. Requests that mutate state without a valid CSRF pairing are rejected **fail-closed**.

## See also

- [Security guide](../guides/security.md)
- [Transports API](../api/transports.md)
