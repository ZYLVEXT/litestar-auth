FROM ghcr.io/astral-sh/uv:0.13.1-python3.14-trixie-slim@sha256:112f89760bd54b63c84d140151ea5f3d849278e54f6f939f2c40a57f3e33d895

ENV UV_CACHE_DIR=/tmp/uv-cache \
    UV_PROJECT_ENVIRONMENT=/opt/sts-venv

WORKDIR /workspace
COPY pyproject.toml uv.lock README.md LICENSE ./
COPY litestar_auth/ litestar_auth/
COPY packages/ packages/
RUN uv sync --frozen --group reference && uv cache clean

WORKDIR /app
