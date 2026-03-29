"""Unit tests for the OAuth client adapter."""

from __future__ import annotations

import importlib
from types import SimpleNamespace
from unittest.mock import AsyncMock

import pytest
from litestar.exceptions import ClientException
from litestar.status_codes import HTTP_400_BAD_REQUEST

from litestar_auth.oauth import client_adapter as client_adapter_module

pytestmark = pytest.mark.unit


def test_client_adapter_module_executes_under_coverage() -> None:
    """Reload the module in-test so definition lines count toward coverage."""
    importlib.reload(client_adapter_module)


async def test_get_account_identity_uses_direct_contract_when_available() -> None:
    """A valid ``get_id_email()`` response is returned unchanged."""
    oauth_client = SimpleNamespace(
        get_id_email=AsyncMock(return_value=("provider-id", "user@example.com")),
    )

    identity = await client_adapter_module.OAuthClientAdapter(oauth_client).get_account_identity("access-token")

    assert identity == ("provider-id", "user@example.com")


async def test_get_account_identity_falls_back_to_profile_when_get_id_email_returns_none() -> None:
    """A ``None`` direct-contract result falls back to profile parsing."""
    oauth_client = SimpleNamespace(
        get_id_email=AsyncMock(return_value=None),
        get_profile=AsyncMock(return_value={"id": "provider-id", "email": "user@example.com"}),
    )

    identity = await client_adapter_module.OAuthClientAdapter(oauth_client).get_account_identity("access-token")

    assert identity == ("provider-id", "user@example.com")
    oauth_client.get_profile.assert_awaited_once_with("access-token")


async def test_get_account_identity_raises_for_malformed_direct_contract_payload() -> None:
    """Malformed non-``None`` tuples still fail loudly."""
    oauth_client = SimpleNamespace(
        get_id_email=AsyncMock(return_value=("provider-id",)),
    )

    with pytest.raises(client_adapter_module.ConfigurationError, match="invalid account identity"):
        await client_adapter_module.OAuthClientAdapter(oauth_client).get_account_identity("access-token")


async def test_get_identity_from_profile_rejects_non_mapping_payload() -> None:
    """Profile payloads must be convertible to mappings."""
    oauth_client = SimpleNamespace(get_profile=AsyncMock(return_value=object()))

    with pytest.raises(client_adapter_module.ConfigurationError, match="invalid profile payload"):
        await client_adapter_module.OAuthClientAdapter(oauth_client)._get_identity_from_profile("access-token")


async def test_get_identity_from_profile_raises_when_email_missing() -> None:
    """Profile parsing preserves the stable missing-email client error."""
    oauth_client = SimpleNamespace(get_profile=AsyncMock(return_value={"id": "provider-id"}))

    with pytest.raises(ClientException) as exc_info:
        await client_adapter_module.OAuthClientAdapter(oauth_client)._get_identity_from_profile("access-token")

    extra = exc_info.value.extra
    assert exc_info.value.status_code == HTTP_400_BAD_REQUEST
    assert (
        extra.get("code") if isinstance(extra, dict) else None
    ) == client_adapter_module.ErrorCode.OAUTH_NOT_AVAILABLE_EMAIL


async def test_get_identity_from_profile_raises_when_account_id_missing() -> None:
    """Profile parsing requires a stable non-empty account identifier."""
    oauth_client = SimpleNamespace(get_profile=AsyncMock(return_value={"email": "user@example.com"}))

    with pytest.raises(client_adapter_module.ConfigurationError, match="account id"):
        await client_adapter_module.OAuthClientAdapter(oauth_client)._get_identity_from_profile("access-token")


async def test_get_email_verified_falls_back_to_profile_when_method_missing() -> None:
    """Missing dedicated verification method falls back to profile parsing."""
    oauth_client = SimpleNamespace(
        get_profile=AsyncMock(return_value={"email_verified": " false "}),
    )

    email_verified = await client_adapter_module.OAuthClientAdapter(oauth_client).get_email_verified("access-token")

    assert email_verified is False


async def test_get_account_identity_and_email_verified_uses_single_profile_fetch() -> None:
    """Combined fallback path parses both values from one profile fetch."""
    oauth_client = SimpleNamespace(
        get_id_email=AsyncMock(return_value=None),
        get_profile=AsyncMock(
            return_value={
                "account_id": "provider-id",
                "account_email": "user@example.com",
                "email_verified": "true",
            },
        ),
    )

    identity, email_verified = await client_adapter_module.OAuthClientAdapter(
        oauth_client,
    ).get_account_identity_and_email_verified(
        "access-token",
    )

    assert identity == ("provider-id", "user@example.com")
    assert email_verified is True
    oauth_client.get_profile.assert_awaited_once_with("access-token")


async def test_get_account_identity_and_email_verified_uses_dedicated_email_verified_when_present() -> None:
    """Profile identity can be combined with dedicated verification when needed."""
    oauth_client = SimpleNamespace(
        get_id_email=AsyncMock(return_value=None),
        get_profile=AsyncMock(return_value={"id": "provider-id", "email": "user@example.com"}),
        get_email_verified=AsyncMock(return_value=True),
    )

    identity, email_verified = await client_adapter_module.OAuthClientAdapter(
        oauth_client,
    ).get_account_identity_and_email_verified(
        "access-token",
    )

    assert identity == ("provider-id", "user@example.com")
    assert email_verified is True
    oauth_client.get_profile.assert_awaited_once_with("access-token")
    oauth_client.get_email_verified.assert_awaited_once_with("access-token")


async def test_get_account_identity_and_email_verified_requires_profile_fallback_method() -> None:
    """Combined fallback still fails loudly without ``get_profile()``."""
    oauth_client = SimpleNamespace(get_id_email=AsyncMock(return_value=None))

    with pytest.raises(client_adapter_module.ConfigurationError, match="get_id_email\\(\\) or get_profile\\(\\)"):
        await client_adapter_module.OAuthClientAdapter(oauth_client).get_account_identity_and_email_verified(
            "access-token",
        )


@pytest.mark.parametrize(
    ("profile", "expected"),
    [
        ({"email_verified": " TRUE "}, True),
        ({"email_verified": "false"}, False),
        ({}, None),
    ],
)
def test_parse_email_verified_from_profile_parses_strings(
    profile: dict[str, object],
    expected: object,
) -> None:
    """Profile parsing normalizes booleans and absent values."""
    assert client_adapter_module._parse_email_verified_from_profile(profile) is expected


def test_parse_email_verified_from_profile_rejects_invalid_string() -> None:
    """Unsupported string values are configuration errors."""
    with pytest.raises(client_adapter_module.ConfigurationError, match="email_verified"):
        client_adapter_module._parse_email_verified_from_profile({"email_verified": "sometimes"})


def test_as_mapping_uses_object_dict_fallback() -> None:
    """Objects with ``__dict__`` are normalized into mappings."""

    class _Payload:
        def __init__(self) -> None:
            self.access_token = "token"
            self.refresh_token = "refresh"

    payload = client_adapter_module._as_mapping(_Payload(), message="invalid")

    assert payload == {"access_token": "token", "refresh_token": "refresh"}


@pytest.mark.parametrize(
    "account_identity",
    [
        None,
        ("provider-id",),
        ("provider-id", "user@example.com", "extra"),
        ("", "user@example.com"),
        ("provider-id", ""),
        ("provider-id", 1),
        ["provider-id", "user@example.com"],
    ],
)
def test_as_account_identity_tuple_rejects_invalid_payloads(account_identity: object) -> None:
    """Only non-empty two-item string tuples satisfy the direct contract."""
    assert client_adapter_module._as_account_identity_tuple(account_identity) is None
