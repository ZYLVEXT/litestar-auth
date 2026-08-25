# Contributing and verification

Install the locked development environment, then run:

```bash
just setup
just check
uv run deptry .
just test
just docs-build
```

`just check` includes Ruff, ty, import-linter, dependency pin validation, and protocol vectors.

Each distribution under `packages/` has an independent CI gate. Run the matching commands from the
changed package directory (replace the placeholders with its distribution and import-package names):

```bash
uv sync --frozen --all-packages --all-extras --group dev
uv run --no-sync python -c "import pathlib, sysconfig; p = pathlib.Path(sysconfig.get_paths()['purelib']) / 'coverage_subprocess.pth'; p.write_text('import coverage; coverage.process_startup()\n')"
cd packages/<distribution>
uv run --no-sync ruff check .
uv run --no-sync ruff format --check --preview .
uv run --no-sync ty check <import_package> tests
COVERAGE_PROCESS_START=pyproject.toml uv run --no-sync pytest \
  --cov=<import_package> --cov-branch --cov-fail-under=100
```

The five values are `authweave-core`/`authweave_core`,
`authweave-workload`/`authweave_workload`, `authweave-otel`/`authweave_otel`,
`authweave-webhooks`/`authweave_webhooks`, and
`authweave-http-signatures`/`authweave_http_signatures`. Run `just build` for the six-distribution
release smoke.

Run `sh docker/reference/verify.sh` for PostgreSQL concurrency, real Redis refresh replay,
TLS 1.3 Envoy termination, local CA/CRL, forged-header replacement, and mock JWKS checks.
Run `sh docker/reference/observability/verify.sh` for the pinned Collector → Prometheus/Tempo/
Grafana smoke and golden metric-name checks.

Changes to authentication behavior require a negative test at the trust boundary. Do not add
fallbacks, deprecated aliases, generic bearer authentication, user-owned shared secrets,
proprietary request signing, or private-key ingestion. Publication and production rollout are
separate operator actions. Maintainers use the [lockstep release and fix-forward procedure](releasing.md).
