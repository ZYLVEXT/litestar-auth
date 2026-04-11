"""Unit tests for the OAuth client adapter."""

from __future__ import annotations

import importlib
from types import SimpleNamespace
from typing import cast
from unittest.mock import AsyncMock

import pytest
from litestar.exceptions import ClientException
from litestar.status_codes import HTTP_400_BAD_REQUEST

from litestar_auth.oauth import client_adapter as client_adapter_module

pytestmark = pytest.mark.unit


def _make_oauth_client(**kwargs: object) -> SimpleNamespace:
    """Return an OAuth client test double with inspectable mock attributes."""
    return SimpleNamespace(**kwargs)


def _build_adapter(oauth_client: object) -> client_adapter_module.OAuthClientAdapter:
    """Return an adapter over a runtime OAuth client double."""
    return client_adapter_module.OAuthClientAdapter(cast("client_adapter_module.OAuthClientProtocol", oauth_client))


def test_client_adapter_module_executes_under_coverage() -> None:
    """Reload the module in-test so definition lines count toward coverage."""
    importlib.reload(client_adapter_module)


def test_oauth_client_adapter_exposes_typed_client_contract_annotation() -> None:
    """The adapter constructor advertises the explicit manual OAuth client protocol."""
    assert client_adapter_module.OAuthClientAdapter.__init__.__annotations__["oauth_client"] == "OAuthClientProtocol"


async def test_get_authorization_url_requires_provider_method() -> None:
    """Manual OAuth clients must expose ``get_authorization_url()`` for login redirects."""
    with pytest.raises(client_adapter_module.ConfigurationError, match="get_authorization_url"):
        await _build_adapter(object()).get_authorization_url(
            redirect_uri="https://app.example/callback",
            state="state",
        )


async def test_get_authorization_url_joins_server_owned_scopes() -> None:
    """The adapter joins configured scopes into the provider's ``scope=`` contract."""
    oauth_client = _make_oauth_client(
        get_authorization_url=AsyncMock(return_value="https://provider.example/authorize"),
    )

    authorization_url = await _build_adapter(oauth_client).get_authorization_url(
        redirect_uri="https://app.example/callback",
        state="state",
        scopes=["openid", "email"],
    )

    assert authorization_url == "https://provider.example/authorize"
    oauth_client.get_authorization_url.assert_awaited_once_with(
        "https://app.example/callback",
        "state",
        scope="openid email",
    )


@pytest.mark.parametrize("authorization_url", [123, ""])
async def test_get_authorization_url_rejects_invalid_provider_response(authorization_url: object) -> None:
    """Manual OAuth clients must return a non-empty authorization URL string."""
    oauth_client = _make_oauth_client(
        get_authorization_url=AsyncMock(return_value=authorization_url),
    )

    with pytest.raises(client_adapter_module.ConfigurationError, match="invalid authorization URL"):
        await _build_adapter(oauth_client).get_authorization_url(
            redirect_uri="https://app.example/callback",
            state="state",
        )


async def test_get_access_token_requires_provider_method() -> None:
    """Manual OAuth clients must expose ``get_access_token()`` for callback exchange."""
    with pytest.raises(client_adapter_module.ConfigurationError, match="get_access_token"):
        await _build_adapter(object()).get_access_token(
            code="provider-code",
            redirect_uri="https://app.example/callback",
        )


async def test_get_access_token_accepts_mapping_payload() -> None:
    """Mapping token payloads are normalized into the supported access-token contract."""
    oauth_client = _make_oauth_client(
        get_access_token=AsyncMock(
            return_value={
                "access_token": "provider-access-token",
                "expires_at": 1_234_567_890,
                "refresh_token": "provider-refresh-token",
            },
        ),
    )

    payload = await _build_adapter(oauth_client).get_access_token(
        code="provider-code",
        redirect_uri="https://app.example/callback",
    )

    assert payload == {
        "access_token": "provider-access-token",
        "expires_at": 1_234_567_890,
        "refresh_token": "provider-refresh-token",
    }


async def test_get_access_token_accepts_object_payload() -> None:
    """Object payloads with ``__dict__`` satisfy the manual token contract."""

    class _TokenPayload:
        def __init__(self) -> None:
            self.access_token = "provider-access-token"
            self.expires_at = None
            self.refresh_token = None

    oauth_client = _make_oauth_client(
        get_access_token=AsyncMock(return_value=_TokenPayload()),
    )

    payload = await _build_adapter(oauth_client).get_access_token(
        code="provider-code",
        redirect_uri="https://app.example/callback",
    )

    assert payload == {
        "access_token": "provider-access-token",
        "expires_at": None,
        "refresh_token": None,
    }


@pytest.mark.parametrize(
    ("payload", "expected_message"),
    [
        ({}, "access_token"),
        ({"access_token": ""}, "access_token"),
        ({"access_token": "provider-access-token", "expires_at": "tomorrow"}, "expires_at"),
        ({"access_token": "provider-access-token", "refresh_token": 123}, "refresh_token"),
        (object(), "invalid access-token payload"),
    ],
)
async def test_get_access_token_rejects_invalid_payload_shapes(
    payload: object,
    expected_message: str,
) -> None:
    """Invalid token payloads fail closed before callback processing continues."""
    oauth_client = _make_oauth_client(
        get_access_token=AsyncMock(return_value=payload),
    )

    with pytest.raises(client_adapter_module.ConfigurationError, match=expected_message):
        await _build_adapter(oauth_client).get_access_token(
            code="provider-code",
            redirect_uri="https://app.example/callback",
        )


async def test_get_account_identity_uses_direct_contract_when_available() -> None:
    """A valid ``get_id_email()`` response is returned unchanged."""
    oauth_client = _make_oauth_client(
        get_id_email=AsyncMock(return_value=("provider-id", "user@example.com")),
    )

    identity = await _build_adapter(oauth_client).get_account_identity("access-token")

    assert identity == ("provider-id", "user@example.com")


async def test_get_account_identity_falls_back_to_profile_when_get_id_email_returns_none() -> None:
    """A ``None`` direct-contract result falls back to profile parsing."""
    oauth_client = _make_oauth_client(
        get_id_email=AsyncMock(return_value=None),
        get_profile=AsyncMock(return_value={"id": "provider-id", "email": "user@example.com"}),
    )

    identity = await _build_adapter(oauth_client).get_account_identity("access-token")

    assert identity == ("provider-id", "user@example.com")
    oauth_client.get_profile.assert_awaited_once_with("access-token")


async def test_get_account_identity_accepts_object_profile_payload() -> None:
    """Profile objects with ``id`` and ``email`` attributes satisfy the fallback contract."""
    oauth_client = _make_oauth_client(
        get_profile=AsyncMock(return_value=SimpleNamespace(id="provider-id", email="user@example.com")),
    )

    identity = await _build_adapter(oauth_client).get_account_identity("access-token")

    assert identity == ("provider-id", "user@example.com")


async def test_get_account_identity_raises_for_malformed_direct_contract_payload() -> None:
    """Malformed non-``None`` tuples still fail loudly."""
    oauth_client = _make_oauth_client(
        get_id_email=AsyncMock(return_value=("provider-id",)),
    )

    with pytest.raises(client_adapter_module.ConfigurationError, match="invalid account identity"):
        await _build_adapter(oauth_client).get_account_identity("access-token")


async def test_get_identity_from_profile_rejects_non_mapping_payload() -> None:
    """Profile payloads must be convertible to mappings."""
    oauth_client = _make_oauth_client(get_profile=AsyncMock(return_value=object()))

    with pytest.raises(client_adapter_module.ConfigurationError, match="invalid profile payload"):
        await _build_adapter(oauth_client)._get_identity_from_profile("access-token")


async def test_get_account_identity_requires_direct_or_profile_contract() -> None:
    """Manual OAuth clients must expose ``get_id_email()`` or ``get_profile()``."""
    with pytest.raises(client_adapter_module.ConfigurationError, match=r"get_id_email\(\) or get_profile\(\)"):
        await _build_adapter(object()).get_account_identity("access-token")


async def test_get_identity_from_profile_raises_when_email_missing() -> None:
    """Profile parsing preserves the stable missing-email client error."""
    oauth_client = _make_oauth_client(get_profile=AsyncMock(return_value={"id": "provider-id"}))

    with pytest.raises(ClientException) as exc_info:
        await _build_adapter(oauth_client)._get_identity_from_profile("access-token")

    extra = exc_info.value.extra
    assert exc_info.value.status_code == HTTP_400_BAD_REQUEST
    assert (
        extra.get("code") if isinstance(extra, dict) else None
    ) == client_adapter_module.ErrorCode.OAUTH_NOT_AVAILABLE_EMAIL


async def test_get_identity_from_profile_raises_when_account_id_missing() -> None:
    """Profile parsing requires a stable non-empty account identifier."""
    oauth_client = _make_oauth_client(get_profile=AsyncMock(return_value={"email": "user@example.com"}))

    with pytest.raises(client_adapter_module.ConfigurationError, match="account id"):
        await _build_adapter(oauth_client)._get_identity_from_profile("access-token")


async def test_get_email_verified_falls_back_to_profile_when_method_missing() -> None:
    """Missing dedicated verification method falls back to profile parsing."""
    oauth_client = _make_oauth_client(
        get_profile=AsyncMock(return_value={"email_verified": " false "}),
    )

    email_verified = await _build_adapter(oauth_client).get_email_verified("access-token")

    assert email_verified is False


async def test_get_email_verified_returns_none_without_helper_or_profile() -> None:
    """Email verification is optional when the provider exposes no verification surface."""
    assert await _build_adapter(object()).get_email_verified("access-token") is None


@pytest.mark.parametrize("verified", [True, False])
async def test_get_email_verified_uses_dedicated_helper(verified: object) -> None:
    """Dedicated ``get_email_verified()`` hooks can be async and return bools directly."""
    oauth_client = _make_oauth_client(
        get_email_verified=AsyncMock(return_value=verified),
    )

    email_verified = await _build_adapter(oauth_client).get_email_verified("access-token")

    assert email_verified is verified


@pytest.mark.parametrize("verified", [True, False])
async def test_get_email_verified_accepts_sync_helper(verified: object) -> None:
    """Dedicated verification hooks may also be synchronous."""
    oauth_client = _make_oauth_client(
        get_email_verified=lambda _access_token: verified,
    )

    email_verified = await _build_adapter(oauth_client).get_email_verified("access-token")

    assert email_verified is verified


async def test_get_email_verified_rejects_invalid_dedicated_helper_value() -> None:
    """Dedicated verification hooks must return bools."""
    oauth_client = _make_oauth_client(
        get_email_verified=AsyncMock(return_value="sometimes"),
    )

    with pytest.raises(client_adapter_module.ConfigurationError, match="verification"):
        await _build_adapter(oauth_client).get_email_verified("access-token")


async def test_get_email_verified_rejects_invalid_profile_value() -> None:
    """Profile fallback must reject non-bool, non-string verification values."""
    oauth_client = _make_oauth_client(
        get_profile=AsyncMock(return_value={"email_verified": 123}),
    )

    with pytest.raises(client_adapter_module.ConfigurationError, match="email_verified"):
        await _build_adapter(oauth_client).get_email_verified("access-token")


async def test_get_account_identity_and_email_verified_uses_single_profile_fetch() -> None:
    """Combined fallback path parses both values from one profile fetch."""
    oauth_client = _make_oauth_client(
        get_id_email=AsyncMock(return_value=None),
        get_profile=AsyncMock(
            return_value={
                "account_id": "provider-id",
                "account_email": "user@example.com",
                "email_verified": "true",
            },
        ),
    )

    identity, email_verified = await _build_adapter(oauth_client).get_account_identity_and_email_verified(
        "access-token",
    )

    assert identity == ("provider-id", "user@example.com")
    assert email_verified is True
    oauth_client.get_profile.assert_awaited_once_with("access-token")


async def test_get_account_identity_and_email_verified_uses_dedicated_email_verified_when_present() -> None:
    """Profile identity can be combined with dedicated verification when needed."""
    oauth_client = _make_oauth_client(
        get_id_email=AsyncMock(return_value=None),
        get_profile=AsyncMock(return_value={"id": "provider-id", "email": "user@example.com"}),
        get_email_verified=AsyncMock(return_value=True),
    )

    identity, email_verified = await _build_adapter(oauth_client).get_account_identity_and_email_verified(
        "access-token",
    )

    assert identity == ("provider-id", "user@example.com")
    assert email_verified is True
    oauth_client.get_profile.assert_awaited_once_with("access-token")
    oauth_client.get_email_verified.assert_awaited_once_with("access-token")


async def test_get_account_identity_and_email_verified_requires_profile_fallback_method() -> None:
    """Combined fallback still fails loudly without ``get_profile()``."""
    oauth_client = _make_oauth_client(get_id_email=AsyncMock(return_value=None))

    with pytest.raises(client_adapter_module.ConfigurationError, match="get_id_email\\(\\) or get_profile\\(\\)"):
        await _build_adapter(oauth_client).get_account_identity_and_email_verified("access-token")


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
