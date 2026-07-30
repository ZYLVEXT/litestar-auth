# authweave-core

Framework-neutral contracts and fail-closed coordination for principal authentication.

```bash
uv add authweave-core
```

The package models verified principals, authentication evidence, immutable request projections,
typed authentication decisions, provider ownership, route policies, and deadline-aware
coordination. It does not depend on a web framework, ORM, cache, or cryptography implementation.

`authweave-core` performs authentication orchestration only. Applications remain responsible for
resource authorization.
