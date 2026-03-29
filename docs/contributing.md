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

For release-quality verification from the repo root (with [`uv`](https://docs.astral.sh/uv/)):

```bash
uv run ruff check --fix .
uv run ruff format .
uv run ty check
uv run deptry .
uv run pytest
```

## Tests

Pyramid and markers are documented in [tests/README.md](https://github.com/ZYLVEXT/litestar-auth/blob/main/tests/README.md) (`unit`, `integration`, `e2e`, `imports`). CI enforces high coverage on `litestar_auth/`.

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

## Style

- Python **3.12+**, **no Pydantic** inside the library’s public contracts where msgspec is used.
- Follow existing patterns; run **`just lint`** and **`just format`** before pushing.
