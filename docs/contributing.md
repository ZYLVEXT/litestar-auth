# Contributing and verification

Install the locked development environment, then run:

```bash
just setup
just check
uv run deptry .
just test
just docs-build
```

The neutral packages have independent gates:

```bash
cd packages/authweave-core
uv run ruff check .
uv run ty check authweave_core tests
COVERAGE_PROCESS_START=pyproject.toml uv run pytest \
  --cov=authweave_core --cov-branch --cov-fail-under=100

cd ../authweave-workload
uv run --extra all ruff check .
uv run --extra all ty check authweave_workload tests
COVERAGE_PROCESS_START=pyproject.toml uv run --extra all pytest \
  --cov=authweave_workload --cov-branch --cov-fail-under=100
```

Run `sh docker/reference/verify.sh` for PostgreSQL concurrency, real Redis refresh replay,
TLS 1.3 Envoy termination, local CA/CRL, forged-header replacement, and mock JWKS checks.

Changes to authentication behavior require a negative test at the trust boundary. Do not add
fallbacks, deprecated aliases, generic bearer authentication, user-owned shared secrets,
proprietary request signing, or private-key ingestion. Publication and production rollout are
separate operator actions.
