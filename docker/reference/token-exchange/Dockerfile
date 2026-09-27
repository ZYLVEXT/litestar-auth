FROM ghcr.io/astral-sh/uv:0.12.19-python3.14-trixie-slim@sha256:a2657d5b8da6a702204e49b2ed2467597da15fb45eb9fee00304c127dad4b1e9

ENV UV_CACHE_DIR=/tmp/uv-cache \
    UV_PROJECT_ENVIRONMENT=/opt/sts-venv

WORKDIR /workspace
COPY pyproject.toml uv.lock README.md LICENSE ./
COPY litestar_auth/ litestar_auth/
COPY packages/ packages/
RUN uv sync --frozen --group reference && uv cache clean

WORKDIR /app
