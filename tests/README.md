## Test suite structure

This repository keeps a strict test pyramid by convention **and** by pytest markers.

### Test levels

- **Unit** (`-m unit`, `tests/unit/`)
  - Fast, deterministic tests for pure logic and error handling.
  - May use mocks/stubs, but avoid mocking Litestar internals unless required.
  - Should not require a real database or full plugin stack wiring.

- **Integration** (`-m integration`, `tests/integration/`)
  - Validates boundaries and wiring: controllers, middleware, plugin configuration, persistence adapters.
  - Uses `litestar.testing.AsyncTestClient` and in-memory implementations where possible.
  - May involve database I/O (e.g., SQLite in-memory) and plugin/middleware wiring.

- **E2E** (`-m e2e`, `tests/e2e/`)
  - Full flows and cross-component invariants (register → verify → login → protected → logout, OAuth flows, etc.).
  - Should be few in number and focused on high-risk user journeys.

### Other markers

- **imports** (`-m imports`): contract tests ensuring the public API surface stays stable.

### Running locally

```bash
uv run pytest -m unit
uv run pytest -m integration
uv run pytest -m e2e
```

### CI intent

CI should run unit/integration/e2e as separate steps (or jobs) and also include at least one `pytest-xdist`
run to catch shared-state coupling early.
