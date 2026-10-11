FROM ghcr.io/astral-sh/uv:0.13.0-python3.14-trixie-slim@sha256:8e70ac2e85d09a5bb7ef09753b80671a60a71c8d24f195e4890d71e03865e36d

ENV UV_CACHE_DIR=/tmp/uv-cache \
    UV_PROJECT_ENVIRONMENT=/opt/sts-venv

WORKDIR /workspace
COPY pyproject.toml uv.lock README.md LICENSE ./
COPY litestar_auth/ litestar_auth/
COPY packages/ packages/
RUN uv sync --frozen --group reference && uv cache clean

WORKDIR /app
