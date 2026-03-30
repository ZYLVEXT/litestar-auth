# Run the full pytest suite.
test:
    uv run pytest

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

# Run all configured pre-commit hooks.
pre-commit:
    uv run pre-commit run --all-files

# Run CI-style checks without auto-fixing files.
check:
    uv run ruff check .
    uv run ruff format --check .
    uv run ty check

# Alias for the dependency audit command.
security: audit
