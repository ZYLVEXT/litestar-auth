"""Unit tests for the OAuth client adapter."""

from __future__ import annotations

import asyncio
import importlib
import inspect
import threading
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


def test_oauth_client_protocols_expose_pkce_keyword_contract() -> None:
    """Manual OAuth protocols advertise the PKCE keyword arguments required by the adapter."""
    authorization_signature = inspect.signature(
        client_adapter_module.OAuthAuthorizationURLClientProtocol.get_authorization_url,
    )
    access_token_signature = inspect.signature(client_adapter_module.OAuthAccessTokenClientProtocol.get_access_token)

    assert authorization_signature.parameters["code_challenge"].kind is inspect.Parameter.KEYWORD_ONLY
    assert authorization_signature.parameters["code_challenge_method"].annotation == "Literal['S256'] | None"
    assert access_token_signature.parameters["code_verifier"].kind is inspect.Parameter.KEYWORD_ONLY
    assert access_token_signature.parameters["code_verifier"].annotation == "str | None"


def test_async_email_verification_protocol_exposes_async_bool_contract() -> None:
    """The new verification protocol is explicitly async and bool-returning."""
    method = client_adapter_module.OAuthEmailVerificationAsyncClientProtocol.get_email_verified

    assert inspect.iscoroutinefunction(method)
    assert method.__annotations__ == {"access_token": "str", "return": "bool"}


def test_async_email_verification_protocol_accepts_runtime_instance_check() -> None:
    """Async verification clients satisfy the runtime-checkable protocol."""

    class _AsyncEmailVerificationClient:
        async def get_email_verified(self, access_token: str) -> bool:
            return access_token == "verified-token"

    assert isinstance(
        _AsyncEmailVerificationClient(),
        client_adapter_module.OAuthEmailVerificationAsyncClientProtocol,
    )


async def test_async_email_verification_protocol_client_is_invoked_with_access_token() -> None:
    """The adapter invokes async verification clients with the provider access token."""

    class _AsyncEmailVerificationClient:
        def __init__(self) -> None:
            self.seen_access_tokens: list[str] = []

        async def get_email_verified(self, access_token: str) -> bool:
            self.seen_access_tokens.append(access_token)
            return True

    oauth_client = _AsyncEmailVerificationClient()

    email_verified = await _build_adapter(oauth_client).get_email_verified("access-token")

    assert email_verified is True
    assert oauth_client.seen_access_tokens == ["access-token"]


@pytest.mark.parametrize("verified", [True, False])
async def test_async_email_verification_protocol_return_value_is_propagated(*, verified: bool) -> None:
    """The adapter returns the async protocol's bool result unchanged."""

    class _AsyncEmailVerificationClient:
        async def get_email_verified(self, access_token: str) -> bool:
            del access_token
            return verified

    assert await _build_adapter(_AsyncEmailVerificationClient()).get_email_verified("access-token") is verified


async def test_async_email_verification_protocol_exception_is_propagated() -> None:
    """Provider failures from the async verification protocol are not swallowed."""

    class _AsyncEmailVerificationClient:
        async def get_email_verified(self, access_token: str) -> bool:
            msg = f"provider rejected {access_token}"
            raise RuntimeError(msg)

    with pytest.raises(RuntimeError, match="provider rejected access-token"):
        await _build_adapter(_AsyncEmailVerificationClient()).get_email_verified("access-token")


def test_sync_email_verification_protocol_exposes_sync_bool_contract() -> None:
    """The sync-only verification protocol stays separate from the async contract."""
    method = client_adapter_module.OAuthEmailVerificationSyncClientProtocol.get_email_verified

    assert not inspect.iscoroutinefunction(method)
    assert method.__annotations__ == {"access_token": "str", "return": "bool"}


def test_make_async_email_verification_client_returns_async_protocol_adapter() -> None:
    """Sync verification clients can be wrapped behind the async-only contract."""

    class _SyncClient:
        def get_email_verified(self, access_token: str) -> bool:
            return access_token == "verified-token"

    async_client = client_adapter_module.make_async_email_verification_client(_SyncClient())

    assert inspect.iscoroutinefunction(async_client.get_email_verified)


async def test_make_async_email_verification_client_offloads_sync_work_from_event_loop() -> None:
    """Blocking sync verification work runs in a worker thread rather than the event loop."""
    event_loop_thread_id = threading.get_ident()
    running_loop = asyncio.get_running_loop()
    observed_thread_ids: list[int] = []
    release_sync_call = threading.Event()
    sync_call_started = asyncio.Event()

    class _SyncClient:
        def get_email_verified(self, access_token: str) -> bool:
            observed_thread_ids.append(threading.get_ident())
            running_loop.call_soon_threadsafe(sync_call_started.set)
            release_sync_call.wait()
            return access_token == "verified-token"

    async_client = client_adapter_module.make_async_email_verification_client(_SyncClient())

    verification_task = asyncio.create_task(async_client.get_email_verified("verified-token"))
    try:
        await asyncio.wait_for(sync_call_started.wait(), timeout=1.0)

        assert not verification_task.done()
        assert observed_thread_ids
        assert observed_thread_ids == [observed_thread_ids[0]]
        assert observed_thread_ids[0] != event_loop_thread_id
    finally:
        release_sync_call.set()

    assert await verification_task is True


@pytest.mark.parametrize("verified", [True, False])
async def test_make_async_email_verification_client_preserves_bool_return_values(*, verified: bool) -> None:
    """Bool verification results from sync clients pass through the async wrapper."""

    class _SyncClient:
        def get_email_verified(self, access_token: str) -> bool:
            del access_token
            return verified

    async_client = client_adapter_module.make_async_email_verification_client(_SyncClient())

    assert await async_client.get_email_verified("access-token") is verified


async def test_make_async_email_verification_client_propagates_sync_exceptions() -> None:
    """Sync client failures still propagate through the async wrapper."""

    class _SyncClient:
        def get_email_verified(self, access_token: str) -> bool:
            msg = f"provider rejected {access_token}"
            raise RuntimeError(msg)

    async_client = client_adapter_module.make_async_email_verification_client(_SyncClient())

    with pytest.raises(RuntimeError, match="provider rejected access-token"):
        await async_client.get_email_verified("access-token")


async def test_make_async_email_verification_client_rejects_non_bool_sync_return_value() -> None:
    """The async wrapper preserves the stable bool-only verification contract."""

    class _SyncClient:
        def get_email_verified(self, access_token: str) -> bool:
            del access_token
            return cast("bool", "sometimes")

    async_client = client_adapter_module.make_async_email_verification_client(_SyncClient())

    with pytest.raises(client_adapter_module.ConfigurationError, match="verification"):
        await async_client.get_email_verified("access-token")


async def test_get_authorization_url_requires_provider_method() -> None:
    """Manual OAuth clients must expose ``get_authorization_url()`` for login redirects."""
    with pytest.raises(client_adapter_module.ConfigurationError, match="get_authorization_url"):
        await _build_adapter(object()).get_authorization_url(
            redirect_uri="https://app.example/callback",
            state="state",
        )


def test_oauth_adapter_validation_error_rejects_non_callable_profile() -> None:
    """Advertised profile hooks must be callable at construction time."""
    oauth_client = _make_oauth_client(get_profile={"id": "provider-id"})

    with pytest.raises(client_adapter_module.ConfigurationError, match="get_profile must be callable"):
        _build_adapter(oauth_client)


def test_oauth_adapter_validation_error_rejects_non_callable_email_verification() -> None:
    """Advertised email-verification hooks must direct users to the supported protocols."""
    oauth_client = _make_oauth_client(get_email_verified=True)

    with pytest.raises(
        client_adapter_module.ConfigurationError,
        match=r"OAuthEmailVerificationAsyncClientProtocol|make_async_email_verification_client",
    ):
        _build_adapter(oauth_client)


def test_oauth_adapter_validation_error_rejects_sync_email_verification() -> None:
    """Direct sync verification hooks must be wrapped before adapter construction."""
    oauth_client = _make_oauth_client(get_email_verified=lambda _access_token: True)

    with pytest.raises(
        client_adapter_module.ConfigurationError,
        match=r"OAuthEmailVerificationAsyncClientProtocol|make_async_email_verification_client",
    ):
        _build_adapter(oauth_client)


def test_oauth_adapter_validation_error_rejects_non_callable_authorization_url() -> None:
    """Advertised authorization URL hooks must be callable for PKCE validation."""
    oauth_client = _make_oauth_client(get_authorization_url="https://provider.example/authorize")

    with pytest.raises(client_adapter_module.ConfigurationError, match="get_authorization_url must be callable"):
        _build_adapter(oauth_client)


def test_oauth_adapter_validation_error_rejects_authorization_url_without_pkce_kwargs() -> None:
    """Legacy authorization URL clients fail closed instead of silently dropping PKCE challenges."""

    async def get_authorization_url(redirect_uri: str, state: str, *, scope: str | None = None) -> str:
        await asyncio.sleep(0)
        del redirect_uri, state, scope
        return "https://provider.example/authorize"

    oauth_client = _make_oauth_client(get_authorization_url=get_authorization_url)

    with pytest.raises(client_adapter_module.ConfigurationError, match=r"PKCE.*code_challenge.*code_challenge_method"):
        _build_adapter(oauth_client)


def test_oauth_adapter_validation_error_rejects_access_token_without_pkce_kwargs() -> None:
    """Legacy token-exchange clients fail closed instead of silently dropping PKCE verifiers."""

    async def get_access_token(code: str, redirect_uri: str) -> dict[str, str]:
        await asyncio.sleep(0)
        del code, redirect_uri
        return {"access_token": "provider-access-token"}

    oauth_client = _make_oauth_client(get_access_token=get_access_token)

    with pytest.raises(client_adapter_module.ConfigurationError, match=r"PKCE.*code_verifier"):
        _build_adapter(oauth_client)


def test_oauth_adapter_validation_error_rejects_factory_client_with_non_callable_profile() -> None:
    """Resolved factory clients receive the same construction-time field validation."""
    oauth_client = _make_oauth_client(get_profile={"id": "provider-id"})

    def oauth_client_factory() -> client_adapter_module.OAuthClientProtocol:
        return cast("client_adapter_module.OAuthClientProtocol", oauth_client)

    with pytest.raises(client_adapter_module.ConfigurationError, match="get_profile must be callable"):
        client_adapter_module._build_oauth_client_adapter(oauth_client_factory=oauth_client_factory)


def test_oauth_adapter_validation_error_rejects_loaded_client_with_non_callable_email_verification() -> None:
    """Loaded class clients receive actionable email-verification validation errors."""
    oauth_client = _make_oauth_client(get_email_verified=True)

    def oauth_client_class_loader(
        oauth_client_class: str,
        /,
        **client_kwargs: object,
    ) -> client_adapter_module.OAuthClientProtocol:
        del oauth_client_class, client_kwargs
        return cast("client_adapter_module.OAuthClientProtocol", oauth_client)

    with pytest.raises(
        client_adapter_module.ConfigurationError,
        match=r"OAuthEmailVerificationAsyncClientProtocol|make_async_email_verification_client",
    ):
        client_adapter_module._build_oauth_client_adapter(
            oauth_client_class="provider.Client",
            oauth_client_class_loader=oauth_client_class_loader,
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
        code_challenge=None,
        code_challenge_method=None,
    )


async def test_get_authorization_url_forwards_pkce_material() -> None:
    """PKCE challenge material is forwarded to clients implementing the new contract."""
    oauth_client = _make_oauth_client(
        get_authorization_url=AsyncMock(return_value="https://provider.example/authorize"),
    )

    authorization_url = await _build_adapter(oauth_client).get_authorization_url(
        redirect_uri="https://app.example/callback",
        state="state",
        code_challenge="challenge",
        code_challenge_method="S256",
    )

    assert authorization_url == "https://provider.example/authorize"
    oauth_client.get_authorization_url.assert_awaited_once_with(
        "https://app.example/callback",
        "state",
        scope=None,
        code_challenge="challenge",
        code_challenge_method="S256",
    )


async def test_get_authorization_url_forwards_httpx_oauth_scope_as_list() -> None:
    """httpx-oauth clients receive the upstream list-shaped scope contract."""

    class _HttpxOAuthClient:
        __module__ = "httpx_oauth.clients.github"

        def __init__(self) -> None:
            self.calls: list[dict[str, object]] = []

        async def get_authorization_url(
            self,
            redirect_uri: str,
            state: str,
            *,
            scope: list[str] | None = None,
            code_challenge: str | None = None,
            code_challenge_method: str | None = None,
        ) -> str:
            self.calls.append(
                {
                    "redirect_uri": redirect_uri,
                    "state": state,
                    "scope": scope,
                    "code_challenge": code_challenge,
                    "code_challenge_method": code_challenge_method,
                },
            )
            return "https://provider.example/authorize"

    oauth_client = _HttpxOAuthClient()

    authorization_url = await _build_adapter(oauth_client).get_authorization_url(
        redirect_uri="https://app.example/callback",
        state="state",
        scopes=["openid", "email"],
        code_challenge="challenge",
        code_challenge_method="S256",
    )

    assert authorization_url == "https://provider.example/authorize"
    assert oauth_client.calls == [
        {
            "redirect_uri": "https://app.example/callback",
            "state": "state",
            "scope": ["openid", "email"],
            "code_challenge": "challenge",
            "code_challenge_method": "S256",
        },
    ]


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
    oauth_client.get_access_token.assert_awaited_once_with(
        "provider-code",
        "https://app.example/callback",
        code_verifier=None,
    )


async def test_get_access_token_forwards_pkce_verifier() -> None:
    """PKCE verifiers are forwarded to clients implementing the new contract."""
    oauth_client = _make_oauth_client(
        get_access_token=AsyncMock(return_value={"access_token": "provider-access-token"}),
    )

    payload = await _build_adapter(oauth_client).get_access_token(
        code="provider-code",
        redirect_uri="https://app.example/callback",
        code_verifier="code-verifier",
    )

    assert payload == {
        "access_token": "provider-access-token",
        "expires_at": None,
        "refresh_token": None,
    }
    oauth_client.get_access_token.assert_awaited_once_with(
        "provider-code",
        "https://app.example/callback",
        code_verifier="code-verifier",
    )


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


def test_supports_async_email_verified_detects_only_coroutine_contract() -> None:
    """Async verification support is identified without accepting sync helpers."""
    async_client = _make_oauth_client(get_email_verified=AsyncMock(return_value=True))
    sync_client = _make_oauth_client(get_email_verified=lambda _access_token: True)

    assert client_adapter_module._supports_async_email_verified(async_client)
    assert not client_adapter_module._supports_async_email_verified(sync_client)


def test_supports_email_verified_rejects_sync_only_contract() -> None:
    """Only async verification clients satisfy the supported verification surface."""
    oauth_client = _make_oauth_client(get_email_verified=lambda _access_token: True)

    assert not client_adapter_module._supports_email_verified(oauth_client)


def test_supports_email_verified_rejects_missing_contract() -> None:
    """Verification support is false when the provider exposes no helper."""
    assert not client_adapter_module._supports_email_verified(object())


def test_supports_email_verified_accepts_async_contract() -> None:
    """Canonical async verification support remains detected."""
    oauth_client = _make_oauth_client(get_email_verified=AsyncMock(return_value=True))

    assert client_adapter_module._supports_email_verified(oauth_client)


@pytest.mark.parametrize("verified", [True, False])
async def test_get_email_verified_uses_dedicated_helper(verified: object) -> None:
    """Dedicated ``get_email_verified()`` hooks can be async and return bools directly."""
    oauth_client = _make_oauth_client(
        get_email_verified=AsyncMock(return_value=verified),
    )

    email_verified = await _build_adapter(oauth_client).get_email_verified("access-token")

    assert email_verified is verified


def test_get_email_verified_rejects_sync_helper_without_wrapper() -> None:
    """Direct sync verification helpers must be wrapped before they reach runtime."""
    oauth_client = _make_oauth_client(
        get_email_verified=lambda _access_token: True,
    )

    with pytest.raises(
        client_adapter_module.ConfigurationError,
        match=r"OAuthEmailVerificationAsyncClientProtocol|make_async_email_verification_client",
    ):
        _build_adapter(oauth_client)


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


async def test_get_account_identity_and_email_verified_propagates_dedicated_verification_config_error() -> None:
    """Combined identity lookup surfaces dedicated verification configuration errors unchanged."""
    oauth_client = _make_oauth_client(
        get_id_email=AsyncMock(return_value=None),
        get_profile=AsyncMock(return_value={"id": "provider-id", "email": "user@example.com"}),
        get_email_verified=AsyncMock(return_value="sometimes"),
    )

    with pytest.raises(client_adapter_module.ConfigurationError, match="verification") as exc_info:
        await _build_adapter(oauth_client).get_account_identity_and_email_verified("access-token")

    assert exc_info.value.code == client_adapter_module.ErrorCode.CONFIGURATION_INVALID
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
