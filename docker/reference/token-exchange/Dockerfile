FROM ghcr.io/astral-sh/uv:0.12.1-python3.14-trixie-slim@sha256:dfe4069fefc02ee4d6097c26f31d0784df09c9b6242fb4a25ad31fbae74ec6aa

ENV UV_CACHE_DIR=/tmp/uv-cache \
    UV_PROJECT_ENVIRONMENT=/opt/sts-venv

WORKDIR /workspace
COPY pyproject.toml uv.lock README.md LICENSE ./
COPY litestar_auth/ litestar_auth/
COPY packages/ packages/
RUN uv sync --frozen --group reference && uv cache clean

WORKDIR /app
