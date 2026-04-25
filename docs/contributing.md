# Contributing

## Local checks

From the repository root (see [justfile](https://github.com/ZYLVEXT/litestar-auth/blob/main/justfile)):

| Command | Purpose |
| ------- | ------- |
| `just test` | Full pytest suite |
| `just lint` | Ruff check with safe fixes |
| `just format` | Ruff format |
| `just typecheck` | Static types (`ty`) |
| `just audit` | Dependency audit (`pip-audit`, `deptry`) |
| `just docs-serve` | Live Zensical preview |
| `just docs-build` | Static site to `site/` |

For release-quality verification from the repo root (with [`uv`](https://docs.astral.sh/uv/)), use the same mandatory block as [AGENTS.md](https://github.com/ZYLVEXT/litestar-auth/blob/main/AGENTS.md#verification):

```bash
uv run ruff check --fix .
uv run ruff format .
uv run ty check
uv run deptry .
uv run pytest --cov --cov-report=term-missing --cov-fail-under=100 -n auto
```

## Tests

Keep the testing docs aligned by audience:

- [Testing plugin-backed apps](guides/testing.md) is the app-level guide for explicit `unsafe_testing`, `AsyncTestClient`, request-scoped session sharing, and auth-state isolation boundaries.
- [tests/README.md](https://github.com/ZYLVEXT/litestar-auth/blob/main/tests/README.md) is the repo-internal guide for the test pyramid, pytest markers (`unit`, `integration`, `e2e`, `imports`), and targeted local runs.

Before claiming completion or opening a PR, run the full verification block above from the repo root. CI enforces high coverage on `litestar_auth/`.

## Documentation maintenance

When you change HTTP routes, **`ErrorCode`** values, or security-sensitive configuration, update the docs in the **same change** as the code. Use this map to find the right page:

| Topic | Primary docs |
| ----- | ------------ |
| Scope / boundaries | [Roadmap](roadmap.md) |
| Architecture | [Architecture](concepts/architecture.md), [Backends](concepts/backends.md), [Request lifecycle](concepts/request_lifecycle.md) |
| HTTP routes | [HTTP API](http_api.md) |
| Flows, errors, operational security | [Security](guides/security.md), [Registration](guides/registration.md), [OAuth](guides/oauth.md), [TOTP](guides/totp.md), [Rate limiting](guides/rate_limiting.md), [Errors](errors.md), [Security overview](security.md) |
| Configuration | [Configuration](configuration.md), [Plugin API](api/plugin.md) |
| Hooks / extension | [Hooks](guides/hooks.md), [Extending](guides/extending.md) |
| Production | [Security](security.md), [Deployment](deployment.md) |

Python API reference pages under `docs/api/` should include short introductory prose before the `::: litestar_auth...` mkdocstrings directive—avoid shipping only the bare directive. For examples of well-structured pages, see [package.md](api/package.md), [models.md](api/models.md), and [guards.md](api/guards.md).

## Style

- Python **3.12+**, **no Pydantic** inside the library’s public contracts where msgspec is used.
- Follow existing patterns; run **`just lint`** and **`just format`** before pushing.
