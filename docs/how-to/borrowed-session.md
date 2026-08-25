# Borrowed request session

Applications with their own request-session integration may pass a typed
`request_session_provider` to `LitestarAuthConfig`. The provider accepts Litestar `State` and
`Scope`, may be synchronous or asynchronous, and is registered under `db_session_dependency_key`
with request-sensitive caching disabled.

It is the authoritative HTTP session source: the same borrowed session is used for authentication,
`authentication_result_hook`, organization lookup, and handler dependency injection. AuthWeave
memoizes the resolved session identity in request scope, so the underlying provider runs once even
though the public dependency remains uncached.

The optional `authentication_result_hook(connection, session, authentication_result)` runs once
for an anonymous or authenticated result, after stale organization context is cleared and before
organization lookup. It may be synchronous or asynchronous and must return `None`; failures stop
the request. Use it only to project application-owned request context, not to replace the verified
authentication result. Rebinding `authentication_result.user` or `.auth` fails closed; mutating the
objects they already reference is not detected.

AuthWeave never commits, rolls back, or closes a provider-returned session. The application session
integration retains lifecycle ownership. Do not combine `request_session_provider` with the legacy
`db_session_dependency_provided_externally=True` flag. A configured `session_maker` remains
available for plugin CLI commands, but is not used by HTTP wiring when a provider is present.

## Related

- [Quickstart](../quickstart.md)
- [Architecture](../architecture.md)
