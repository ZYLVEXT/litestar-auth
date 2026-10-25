FROM ghcr.io/astral-sh/uv:0.13.5-python3.14-trixie-slim@sha256:d8e732839dfc4225a1ff698803b478b2223c05636c055d3add41ab9dbec0f315

ENV UV_CACHE_DIR=/tmp/uv-cache \
    UV_PROJECT_ENVIRONMENT=/opt/sts-venv

WORKDIR /workspace
COPY pyproject.toml uv.lock README.md LICENSE ./
COPY litestar_auth/ litestar_auth/
COPY packages/ packages/
RUN uv sync --frozen --group reference && uv cache clean

WORKDIR /app
