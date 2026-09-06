FROM ghcr.io/astral-sh/uv:0.12.10-python3.14-trixie-slim@sha256:d5ddd498c5a28ec77ff1c70276f8f3c4a116a303c8b5583a018ea43c2e89e366

ENV UV_CACHE_DIR=/tmp/uv-cache \
    UV_PROJECT_ENVIRONMENT=/opt/sts-venv

WORKDIR /workspace
COPY pyproject.toml uv.lock README.md LICENSE ./
COPY litestar_auth/ litestar_auth/
COPY packages/ packages/
RUN uv sync --frozen --group reference && uv cache clean

WORKDIR /app
