# Cookbook: Refresh flow with cookies

Long-lived sessions often use a **refresh** token in a separate cookie or body field while keeping the access token short-lived.

## Enable refresh

Set on `LitestarAuthConfig`:

```python
enable_refresh=True
```

Your **strategy** must implement refresh semantics (e.g. rotating refresh tokens for database/Redis strategies, or refresh cookie handling for JWT setups). The auth controller exposes:

- `POST {auth_path}/refresh`

when `enable_refresh` is true.

## Cookie-specific notes

When using `CookieTransport`, refresh may use a dedicated refresh cookie name configured on the transport. Ensure **CSRF** rules still cover unsafe methods that refresh or rotate sessions.

## Tests

Integration coverage lives under `tests/integration/` and `tests/e2e/` for refresh flows — use them as executable reference when tuning cookie parameters.

## See also

- [HTTP API — Auth core](../http_api.md)
- [Strategies](../api/strategies.md)
