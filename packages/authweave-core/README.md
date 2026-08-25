# authweave-core

Framework-neutral contracts and fail-closed coordination for principal authentication.

```bash
uv add authweave-core
```

The package models verified principals, authentication evidence, immutable request projections,
typed authentication decisions, provider ownership, route policies, and deadline-aware
coordination. It does not depend on a web framework, ORM, cache, or cryptography implementation.

`AuthenticationRuntime(observer=...)` accepts the minimal `SecurityObserver`
protocol. The observation boundary is a no-op when absent and isolates observer
enter/outcome/exit failures with rate-limited warnings. Implementations such as
`authweave-otel` remain optional; core never imports OpenTelemetry.

`authweave-core` performs authentication orchestration only. Applications remain responsible for
resource authorization.

Docs: [AuthWeave architecture](https://zylvext.github.io/litestar-auth/architecture/) and
[API reference](https://zylvext.github.io/litestar-auth/api/authweave-core/).
