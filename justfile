# Sync the dev environment and install the coverage subprocess startup hook.
# The hook is the canonical mechanism (per coverage.py docs) for measuring
# import-time code that pytest-cov would otherwise miss because the package is
# imported during pytest plugin discovery, before instrumentation starts.
# Idempotent: rewrites the .pth file each run because `uv sync --frozen` may
# rebuild the venv from scratch.
setup:
    uv sync --frozen --all-extras --group dev
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
    uv run deptry .

# Build source and wheel distributions.
build:
    uv build

# Serve documentation locally (Zensical, config in zensical.toml).
docs-serve:
    uv run --group docs zensical serve

# Build static documentation site.
docs-build:
    uv run --group docs zensical build

# Run all configured prek hooks.
prek:
    uv run prek run --all-files

# Run CI-style checks without auto-fixing files.
check:
    uv run ruff check .
    uv run ruff format --check .
    uv run ty check

# Alias for the dependency audit command.
security: audit
