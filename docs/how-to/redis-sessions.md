# Redis sessions and refresh

Install `litestar-auth[redis]` and configure exactly one `CookieTransport` + `RedisTokenStrategy`
backend. Do not combine database and Redis session providers or add credential fallback.

Both database and Redis strategies issue **opaque** server-side access tokens. They are not bearer
JWTs for browser clients. See [credentials and tokens](../credentials.md).

With `LitestarAuthConfig.enable_refresh=True`:

- refresh tokens rotate on use;
- reuse of a consumed refresh token revokes the active chain;
- create the refresh-token and consumed-refresh-digest tables (database) or equivalent Redis keys.

Multi-worker deployments must point every worker at the same Redis (or database) session and
replay stores. Process-local stores do not give cluster-wide revocation or refresh-replay
guarantees. See [multi-worker stores](multi-worker-stores.md).

The runnable
[`demo_db_token_refresh`](https://github.com/ZYLVEXT/litestar-auth/tree/main/examples/demo_db_token_refresh)
covers the database refresh path end to end.

## Related

- [Quickstart](../quickstart.md)
- [Secrets and stores](../secrets.md)
- [Security posture](../security.md)
