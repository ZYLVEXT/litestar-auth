# Sync the dev environment and install the coverage subprocess startup hook.
# The hook is the canonical mechanism (per coverage.py docs) for measuring
# import-time code that pytest-cov would otherwise miss because the package is
# imported during pytest plugin discovery, before instrumentation starts.
# Idempotent: rewrites the .pth file each run because `uv sync --frozen` may
# rebuild the venv from scratch.
setup:
    uv sync --frozen --all-packages --all-extras --group dev
    @uv run python -c "import sysconfig, pathlib; \
        p = pathlib.Path(sysconfig.get_paths()['purelib']) / 'coverage_subprocess.pth'; \
        p.write_text('import coverage; coverage.process_startup()\n'); \
        print(f'Installed coverage subprocess hook at {p}')"

# Run the full pytest suite under coverage.
# COVERAGE_PROCESS_START activates the coverage_subprocess.pth hook (installed
# by `just setup`), which starts coverage at Python interpreter startup so
# import-time class/function definitions are measured even when pytest-cov
# imports `litestar_auth` early during plugin discovery.
test:
    COVERAGE_PROCESS_START=pyproject.toml uv run pytest --cov --cov-report=term-missing --cov-fail-under=100 -n auto

# Lint the codebase and apply safe Ruff fixes.
lint:
    uv run ruff check --fix .

# Format the codebase with Ruff.
format:
    uv run ruff format .

# Check formatting without changing files.
format-check:
    uv run ruff format --check .

# Run static type checks with ty.
typecheck:
    uv run ty check

# Audit dependencies for known vulnerabilities and dependency issues.
audit:
    uv run pip-audit
    just deptry-check

# Check dependency declarations for the root project and every distribution.
deptry-check:
    uv run deptry .
    for project in packages/*; do (cd "$project" && uv run --no-sync deptry .) || exit; done

# Check import boundaries across the lockstep workspace.
lint-imports:
    uv run --no-sync lint-imports

# Build source and wheel distributions for the lockstep workspace release.
build:
    uv run --no-sync python scripts/release_artifacts.py build --dist-dir dist
    uv run --no-sync python scripts/release_artifacts.py smoke --dist-dir dist

# Serve documentation locally (Zensical, config in zensical.toml).
docs-serve:
    uv run --group docs zensical serve

# Build static documentation site.
docs-build:
    mkdir -p site
    uv run --group docs zensical build --clean

# Run all configured prek hooks.
prek:
    uv run prek run --all-files

# Run CI-style checks without auto-fixing files.
check:
    uv run ruff check .
    uv run ruff format --check .
    uv run ty check
    uv run --no-sync python scripts/validate_dependency_pins.py
    just lint-imports
    just vectors-check

# Validate immutable GitHub Action and Docker image pins.
dependency-pins-check:
    uv run --no-sync python scripts/validate_dependency_pins.py

# Verify the published protocol vectors against their owning implementations.
vectors-check:
    for verifier in docs/vectors/*/*/verify_vectors.py; do uv run --no-sync python "$verifier" || exit; done

# Alias for the dependency audit command.
security: audit
