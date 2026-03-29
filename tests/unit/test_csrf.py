"""Unit tests for Litestar's built-in CSRF configuration."""

from __future__ import annotations

import pytest
from litestar import Litestar, get, post
from litestar.config.csrf import CSRFConfig
from litestar.testing import AsyncTestClient

pytestmark = pytest.mark.unit

CSRF_COOKIE_NAME = "litestar_auth_csrf"
CSRF_HEADER_NAME = "X-CSRF-Token"
HTTP_FORBIDDEN = 403
HTTP_CREATED = 201
HTTP_OK = 200


@get("/csrf", sync_to_thread=False)
def csrf_seed() -> dict[str, bool]:
    """Return a safe response that seeds the CSRF cookie."""
    return {"seeded": True}


@post("/csrf", sync_to_thread=False)
def csrf_protected() -> dict[str, bool]:
    """Return a successful response once CSRF validation passes."""
    return {"ok": True}


def _build_app() -> Litestar:
    return Litestar(
        route_handlers=[csrf_seed, csrf_protected],
        csrf_config=CSRFConfig(
            secret="c" * 32,
            cookie_name=CSRF_COOKIE_NAME,
            header_name=CSRF_HEADER_NAME,
            cookie_secure=False,
        ),
    )


async def test_csrf_config_sets_cookie_on_safe_request() -> None:
    """GET requests seed the configured CSRF cookie automatically."""
    async with AsyncTestClient(app=_build_app()) as client:
        response = await client.get("/csrf")

    assert response.status_code == HTTP_OK
    assert response.cookies.get(CSRF_COOKIE_NAME)


async def test_csrf_config_rejects_unsafe_request_without_header() -> None:
    """POST requests fail when the CSRF header is missing."""
    async with AsyncTestClient(app=_build_app()) as client:
        await client.get("/csrf")
        response = await client.post("/csrf")

    assert response.status_code == HTTP_FORBIDDEN
    assert response.json()["detail"] == "CSRF token verification failed"


async def test_csrf_config_accepts_matching_cookie_and_header() -> None:
    """POST requests succeed when the request echoes the seeded CSRF token."""
    async with AsyncTestClient(app=_build_app()) as client:
        seed_response = await client.get("/csrf")
        csrf_token = seed_response.cookies.get(CSRF_COOKIE_NAME)
        assert csrf_token is not None

        response = await client.post("/csrf", headers={CSRF_HEADER_NAME: csrf_token})

    assert response.status_code == HTTP_CREATED
    assert response.json() == {"ok": True}
