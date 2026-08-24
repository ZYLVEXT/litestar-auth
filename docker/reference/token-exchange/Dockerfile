FROM ghcr.io/astral-sh/uv:0.12.5-python3.14-trixie-slim@sha256:dc360d7e5f968c682e8b59e83027a315a0232dead15cb9dfe3e707a12ba390e1

ENV UV_CACHE_DIR=/tmp/uv-cache \
    UV_PROJECT_ENVIRONMENT=/opt/sts-venv

WORKDIR /workspace
COPY pyproject.toml uv.lock README.md LICENSE ./
COPY litestar_auth/ litestar_auth/
COPY packages/ packages/
RUN uv sync --frozen --group reference && uv cache clean

WORKDIR /app
