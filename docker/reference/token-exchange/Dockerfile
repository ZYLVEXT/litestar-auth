FROM ghcr.io/astral-sh/uv:0.13.8-python3.14-trixie-slim@sha256:81a1340fea1e72ad4a8e9a016128b0c61041cf182ea49fd788023e52842bc147

ENV UV_CACHE_DIR=/tmp/uv-cache \
    UV_PROJECT_ENVIRONMENT=/opt/sts-venv

WORKDIR /workspace
COPY pyproject.toml uv.lock README.md LICENSE ./
COPY litestar_auth/ litestar_auth/
COPY packages/ packages/
RUN uv sync --frozen --group reference && uv cache clean

WORKDIR /app
