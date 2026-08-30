FROM ghcr.io/astral-sh/uv:0.12.7-python3.14-trixie-slim@sha256:0e664b12a6be9cd16be1015ec5cc3feebdeb42078ab587389707afbdfab8b10f

ENV UV_CACHE_DIR=/tmp/uv-cache \
    UV_PROJECT_ENVIRONMENT=/opt/sts-venv

WORKDIR /workspace
COPY pyproject.toml uv.lock README.md LICENSE ./
COPY litestar_auth/ litestar_auth/
COPY packages/ packages/
RUN uv sync --frozen --group reference && uv cache clean

WORKDIR /app
