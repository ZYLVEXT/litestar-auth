# Quickstart

This walkthrough wires **one** authentication backend: **Bearer** transport + **JWT** strategy, with the default SQLAlchemy user model from `litestar_auth.models`.

## 1. Dependencies

Install the library and an async SQLite driver if you follow the snippet literally:

```bash
uv add litestar-auth aiosqlite
```

For PostgreSQL or MySQL, use the appropriate `sqlalchemy` async driver instead.

## 2. Create tables

The bundled `User` model (and related token/OAuth tables if you use those features) must exist in your database. Use Alembic or `metadata.create_all` in a migration — not shown here.

## 3. Application code

The following matches the pattern used in the test suite: build a `LitestarAuthConfig`, pass it to `LitestarAuth`, and register the plugin on `Litestar`.

```python
--8<-- "docs/snippets/quickstart_plugin.py"
```

## 4. Provide a database session

- `session_maker` is a callable factory the plugin invokes as `session_maker()` to obtain the shared request-local `AsyncSession`. The snippet uses `async_sessionmaker(...)`, which is the common implementation.
- **`session_maker` set** (as in the snippet above): the plugin registers a request-scoped `AsyncSession` provider under `LitestarAuthConfig.db_session_dependency_key` (default `db_session`). You do not need to wire that dependency yourself.
- **Your app already provides a session**: set `db_session_dependency_provided_externally=True` and ensure something else injects `AsyncSession` under the same key (or change the key with `db_session_dependency_key`).
- **Custom dependency name only**: keep `session_maker` and set `db_session_dependency_key` to match your handlers’ parameter name.

## 5. Call the API

With defaults, log in at `POST /auth/login` and send `Authorization: Bearer <access_token>` on protected routes. See [HTTP API](http_api.md) for the full surface.

## Next steps

- [Concepts — Architecture](concepts/architecture.md) — how pieces fit together.
- [Configuration](configuration.md) — all `LitestarAuthConfig` fields.
- [Security](security.md) — CSRF, cookies, JWT revocation, and production flags.
