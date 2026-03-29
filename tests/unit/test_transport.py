"""Tests for authentication transports."""

from __future__ import annotations

import importlib
from typing import TYPE_CHECKING, Any, cast

import pytest
from litestar.connection import ASGIConnection
from litestar.enums import MediaType
from litestar.response import Response

import litestar_auth.authentication.transport.bearer as bearer_module
import litestar_auth.authentication.transport.cookie as cookie_module
from litestar_auth.authentication.transport.base import LogoutTokenReadable, Transport
from litestar_auth.authentication.transport.cookie import CookieTransport

if TYPE_CHECKING:
    from litestar.datastructures.cookie import Cookie
    from litestar.types import HTTPScope

pytestmark = pytest.mark.unit
CUSTOM_COOKIE_MAX_AGE = 3600
EXPECTED_COOKIE_COUNT = 1


def _get_response_cookie(response: Response[Any], key: str) -> Cookie:
    """Return the cookie with the given key from a response."""
    return next(cookie for cookie in response.cookies if cookie.key == key)


def _build_connection(authorization: str | None = None) -> ASGIConnection[Any, Any, Any, Any]:
    """Create a minimal connection with an optional Authorization header.

    Returns:
        A connection with the provided Authorization header.
    """
    headers: list[tuple[bytes, bytes]] = []
    if authorization is not None:
        headers.append((b"authorization", authorization.encode()))

    scope = {
        "type": "http",
        "headers": headers,
        "path_params": {},
        "query_string": b"",
    }
    return ASGIConnection(scope=cast("HTTPScope", scope))


def _build_cookie_connection(**cookies: str) -> ASGIConnection[Any, Any, Any, Any]:
    """Create a minimal connection with the provided cookies.

    Returns:
        A connection carrying the provided ``Cookie`` header.
    """
    cookie_header = "; ".join(f"{key}={value}" for key, value in cookies.items())
    headers = [(b"cookie", cookie_header.encode())] if cookie_header else []
    scope = {
        "type": "http",
        "headers": headers,
        "path_params": {},
        "query_string": b"",
    }
    return ASGIConnection(scope=cast("HTTPScope", scope))


async def test_bearer_transport_reads_valid_authorization_header() -> None:
    """BearerTransport extracts the token part from a valid bearer header."""
    transport = bearer_module.BearerTransport()

    assert isinstance(transport, Transport)
    assert await transport.read_token(_build_connection("Bearer example-token")) == "example-token"
    assert await transport.read_token(_build_connection("bearer lowercase-token")) == "lowercase-token"


def test_bearer_transport_does_not_expose_explicit_logout_token_reader() -> None:
    """BearerTransport relies on backend fallback instead of a dedicated logout reader."""
    transport = bearer_module.BearerTransport()

    assert not isinstance(transport, LogoutTokenReadable)


async def test_bearer_transport_rejects_missing_or_invalid_authorization_header() -> None:
    """BearerTransport returns ``None`` for missing or malformed headers."""
    transport = bearer_module.BearerTransport()

    assert await transport.read_token(_build_connection()) is None
    assert await transport.read_token(_build_connection("Basic abc123")) is None
    assert await transport.read_token(_build_connection("Bearer")) is None
    assert await transport.read_token(_build_connection("Bearer ")) is None
    assert await transport.read_token(_build_connection("Bearer   ")) is None
    assert await transport.read_token(_build_connection("Bearer \t")) is None


def test_bearer_transport_sets_login_token_in_response_body() -> None:
    """BearerTransport writes the token payload into the response body."""
    transport = bearer_module.BearerTransport()
    response = Response(None)

    result = transport.set_login_token(response, "issued-token")

    assert result is response
    assert response.content == {"access_token": "issued-token", "token_type": "bearer"}
    assert response.media_type == MediaType.JSON


def test_bearer_transport_clears_response_body_on_logout() -> None:
    """BearerTransport removes any login payload when logging out."""
    transport = bearer_module.BearerTransport()
    response = Response({"access_token": "issued-token"})

    result = transport.set_logout(response)

    assert result is response
    assert response.content is None


async def test_bearer_transport_module_reload_preserves_public_class() -> None:
    """Reloading the bearer module preserves the public transport behavior under coverage."""
    reloaded_module = importlib.reload(bearer_module)
    transport = reloaded_module.BearerTransport()
    response = Response({"stale": "value"})

    assert reloaded_module.BearerTransport.__name__ == "BearerTransport"
    assert await transport.read_token(_build_connection("Bearer reloaded-token")) == "reloaded-token"
    assert await transport.read_token(_build_connection("Basic rejected")) is None
    assert await transport.read_token(_build_connection("Bearer \t")) is None
    assert transport.set_login_token(response, "reloaded-issued-token") is response
    assert response.content == {"access_token": "reloaded-issued-token", "token_type": "bearer"}
    assert response.media_type == MediaType.JSON
    assert transport.set_logout(response) is response
    assert response.content is None


async def test_cookie_transport_reads_token_from_named_cookie() -> None:
    """CookieTransport reads the configured cookie value from the request."""
    transport = CookieTransport(cookie_name="session")

    assert isinstance(transport, Transport)
    assert await transport.read_token(_build_cookie_connection(session="issued-token")) == "issued-token"
    assert await transport.read_token(_build_cookie_connection(other="value")) is None


async def test_cookie_transport_read_logout_token_uses_access_cookie_only() -> None:
    """Cookie logout token sourcing reads the access cookie, not refresh cookies."""
    transport = CookieTransport(cookie_name="session")

    assert isinstance(transport, LogoutTokenReadable)
    assert await transport.read_logout_token(_build_cookie_connection(session="access-token")) == "access-token"
    assert await transport.read_logout_token(_build_cookie_connection(session_refresh="refresh-token")) is None


def test_cookie_security_login_uses_hardened_set_cookie_defaults() -> None:
    """CookieTransport stores login tokens with hardened default cookie flags."""
    transport = CookieTransport()
    response = Response(None)

    result = transport.set_login_token(response, "issued-token")

    assert result is response
    assert len(response.cookies) == EXPECTED_COOKIE_COUNT
    cookie = next(cookie for cookie in response.cookies if cookie.key == "litestar_auth")
    assert cookie.key == "litestar_auth"
    assert cookie.value == "issued-token"
    assert cookie.max_age is None
    assert cookie.path == "/"
    assert cookie.domain is None
    assert cookie.secure is True
    assert cookie.httponly is True
    assert cookie.samesite == "lax"
    set_cookie = cookie.to_encoded_header()[1].decode().lower()
    assert "litestar_auth=issued-token" in set_cookie
    assert "path=/" in set_cookie
    assert "secure" in set_cookie
    assert "httponly" in set_cookie
    assert "samesite=lax" in set_cookie


def test_cookie_transport_honors_custom_cookie_configuration() -> None:
    """CookieTransport forwards constructor configuration into cookies."""
    transport = CookieTransport(
        cookie_name="custom-auth",
        max_age=CUSTOM_COOKIE_MAX_AGE,
        path="/api",
        domain="example.com",
        secure=False,
        httponly=False,
        samesite="strict",
    )
    response = Response(None)

    result = transport.set_login_token(response, "custom-token")

    assert result is response
    assert len(response.cookies) == EXPECTED_COOKIE_COUNT
    cookie = next(cookie for cookie in response.cookies if cookie.key == "custom-auth")
    assert cookie.key == "custom-auth"
    assert cookie.value == "custom-token"
    assert cookie.max_age == CUSTOM_COOKIE_MAX_AGE
    assert cookie.path == "/api"
    assert cookie.domain == "example.com"
    assert cookie.secure is False
    assert cookie.httponly is False
    assert cookie.samesite == "strict"


def test_cookie_transport_exposes_refresh_cookie_name_from_cookie_name() -> None:
    """CookieTransport derives a separate refresh-cookie key from the access-cookie name."""
    transport = CookieTransport(cookie_name="custom-auth")

    assert transport.refresh_cookie_name == "custom-auth_refresh"


def test_cookie_transport_module_reload_preserves_public_class() -> None:
    """Reloading the module preserves the public transport class definition."""
    reloaded_module = importlib.reload(cookie_module)

    assert reloaded_module.CookieTransport.__name__ == "CookieTransport"


def test_cookie_transport_rejects_insecure_samesite_none_without_secure() -> None:
    """SameSite=None cookies must be Secure to avoid CSRF-downgrade and browser rejection."""
    with pytest.raises(ValueError, match=r"samesite=\"none\" requires secure=True"):
        CookieTransport(secure=False, samesite="none")


def test_cookie_security_logout_keeps_hardened_cookie_flags() -> None:
    """CookieTransport deletes cookies by issuing an immediate-expiry cookie."""
    transport = CookieTransport(
        cookie_name="session",
        path="/auth",
        domain="example.com",
        httponly=True,
    )
    response = Response(None)

    result = transport.set_logout(response)

    assert result is response
    assert len(response.cookies) == EXPECTED_COOKIE_COUNT
    cookie = next(cookie for cookie in response.cookies if cookie.key == "session")
    assert cookie.key == "session"
    assert not cookie.value
    assert cookie.max_age == 0
    assert cookie.path == "/auth"
    assert cookie.domain == "example.com"
    assert cookie.secure is True
    assert cookie.httponly is True
    assert cookie.samesite == "lax"
    set_cookie = cookie.to_encoded_header()[1].decode().lower()
    assert "session=" in set_cookie
    assert "max-age=0" in set_cookie
    assert "domain=example.com" in set_cookie
    assert "path=/auth" in set_cookie
    assert "secure" in set_cookie
    assert "httponly" in set_cookie
    assert "samesite=lax" in set_cookie


def test_cookie_security_logout_does_not_clear_refresh_cookie() -> None:
    """CookieTransport logout clears only the transport-managed auth cookie."""
    transport = CookieTransport()
    response = Response(None)

    transport.set_logout(response)

    assert not any(cookie.key == "litestar_auth_refresh" for cookie in response.cookies)


def test_cookie_transport_sets_refresh_cookie_with_dedicated_max_age() -> None:
    """CookieTransport stores refresh tokens in a dedicated HttpOnly cookie."""
    transport = CookieTransport(
        cookie_name="session",
        max_age=CUSTOM_COOKIE_MAX_AGE,
        refresh_max_age=CUSTOM_COOKIE_MAX_AGE * 2,
        path="/auth",
        domain="example.com",
        secure=False,
        samesite="strict",
    )
    response = Response(None)

    result = transport.set_refresh_token(response, "refresh-token")

    assert result is response
    assert len(response.cookies) == EXPECTED_COOKIE_COUNT
    cookie = _get_response_cookie(response, "session_refresh")
    assert cookie.value == "refresh-token"
    assert cookie.max_age == CUSTOM_COOKIE_MAX_AGE * 2
    assert cookie.path == "/auth"
    assert cookie.domain == "example.com"
    assert cookie.secure is False
    assert cookie.httponly is True
    assert cookie.samesite == "strict"


def test_cookie_transport_refresh_cookie_falls_back_to_access_cookie_max_age() -> None:
    """Refresh cookies reuse the access max-age when no dedicated refresh max-age is configured."""
    transport = CookieTransport(cookie_name="session", max_age=CUSTOM_COOKIE_MAX_AGE)
    response = Response(None)

    transport.set_refresh_token(response, "refresh-token")

    cookie = _get_response_cookie(response, "session_refresh")
    assert cookie.max_age == CUSTOM_COOKIE_MAX_AGE


def test_cookie_transport_clears_refresh_cookie_with_immediate_expiry() -> None:
    """CookieTransport clears refresh cookies by issuing an empty zero-max-age cookie."""
    transport = CookieTransport(cookie_name="session", path="/auth", domain="example.com")
    response = Response(None)

    result = transport.clear_refresh_token(response)

    assert result is response
    assert len(response.cookies) == EXPECTED_COOKIE_COUNT
    cookie = _get_response_cookie(response, "session_refresh")
    assert not cookie.value
    assert cookie.max_age == 0
    assert cookie.path == "/auth"
    assert cookie.domain == "example.com"
    assert cookie.secure is True
    assert cookie.httponly is True
    assert cookie.samesite == "lax"


def test_cookie_transport_preserves_allow_insecure_cookie_auth_flag() -> None:
    """CookieTransport stores the explicit unsafe-override flag for plugin validation."""
    transport = CookieTransport()
    unsafe_transport = CookieTransport(allow_insecure_cookie_auth=True)

    assert transport.allow_insecure_cookie_auth is False
    assert unsafe_transport.allow_insecure_cookie_auth is True
