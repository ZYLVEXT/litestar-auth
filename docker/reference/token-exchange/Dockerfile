FROM ghcr.io/astral-sh/uv:0.12.13-python3.14-trixie-slim@sha256:d2525beeae88affd18389bf69292abf9b5cbbb3f5c5242b6da3d20e304959b37

ENV UV_CACHE_DIR=/tmp/uv-cache \
    UV_PROJECT_ENVIRONMENT=/opt/sts-venv

WORKDIR /workspace
COPY pyproject.toml uv.lock README.md LICENSE ./
COPY litestar_auth/ litestar_auth/
COPY packages/ packages/
RUN uv sync --frozen --group reference && uv cache clean

WORKDIR /app
