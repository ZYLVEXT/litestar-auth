"""Tests for API-key authentication transport."""

from __future__ import annotations

from typing import Any, cast

import pytest
from litestar.connection import ASGIConnection
from litestar.response import Response

from litestar_auth.authentication.transport import ApiKeyTransport, Transport
from litestar_auth.exceptions import TokenError

pytestmark = pytest.mark.unit


def _build_connection(
    *,
    authorization: str | None = None,
    api_key: str | None = None,
) -> ASGIConnection[Any, Any, Any, Any]:
    headers: list[tuple[bytes, bytes]] = []
    if authorization is not None:
        headers.append((b"authorization", authorization.encode()))
    if api_key is not None:
        headers.append((b"x-api-key", api_key.encode()))
    scope = {"type": "http", "headers": headers, "path_params": {}, "query_string": b""}
    return ASGIConnection(scope=cast("Any", scope))


async def test_api_key_transport_reads_bearer_or_x_api_key_header() -> None:
    """ApiKeyTransport accepts canonical API keys from both supported headers."""
    transport = ApiKeyTransport()
    token = "ak_prod_keyid.secret"

    assert isinstance(transport, Transport)
    assert await transport.read_token(_build_connection(authorization=f"Bearer {token}")) == token
    assert await transport.read_token(_build_connection(authorization=f"bearer {token}")) == token
    assert await transport.read_token(_build_connection(api_key=token)) == token


@pytest.mark.parametrize(
    "authorization",
    [
        pytest.param(None, id="missing"),
        pytest.param("Basic ak_prod_keyid.secret", id="wrong-scheme"),
        pytest.param("Bearer jwt-token", id="non-api-key-bearer"),
        pytest.param("Bearer", id="missing-token"),
    ],
)
async def test_api_key_transport_ignores_missing_malformed_or_non_api_key_authorization(
    authorization: str | None,
) -> None:
    """Mismatched schemes and non-API-key bearer values are ignored."""
    transport = ApiKeyTransport()

    assert await transport.read_token(_build_connection(authorization=authorization)) is None


async def test_api_key_transport_prefers_authorization_header_over_x_api_key() -> None:
    """Authorization wins when both supported API-key headers are present."""
    transport = ApiKeyTransport()

    assert (
        await transport.read_token(
            _build_connection(authorization="Bearer ak_prod_auth.secret", api_key="ak_prod_header.secret"),
        )
        == "ak_prod_auth.secret"
    )


async def test_api_key_transport_ignores_non_api_key_x_api_key_header() -> None:
    """X-API-Key values must still use the canonical API-key prefix."""
    assert await ApiKeyTransport().read_token(_build_connection(api_key="plain-secret")) is None


def test_api_key_transport_rejects_login_token_issuance() -> None:
    """API keys are not issued by the login flow."""
    with pytest.raises(TokenError, match="cannot issue login tokens"):
        ApiKeyTransport().set_login_token(Response(None), "ak_prod_keyid.secret")


def test_api_key_transport_logout_keeps_response_unchanged() -> None:
    """API-key transport has no client-managed state to clear."""
    response = Response({"ok": True})

    assert ApiKeyTransport().set_logout(response) is response
