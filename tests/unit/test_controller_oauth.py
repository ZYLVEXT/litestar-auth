"""Unit tests for OAuth controller helpers: state validation, authorization URL, access token, account identity."""

from __future__ import annotations

import asyncio
import importlib
from types import SimpleNamespace
from typing import Any, cast
from unittest.mock import AsyncMock, MagicMock

import pytest
from litestar import Router
from litestar.exceptions import ClientException
from litestar.response import Response
from litestar.response.redirect import Redirect
from litestar.status_codes import HTTP_400_BAD_REQUEST

import litestar_auth.controllers.oauth as oauth_module
from litestar_auth.controllers._utils import _require_account_state
from litestar_auth.controllers.oauth import (
    STATE_COOKIE_MAX_AGE,
    _clear_state_cookie,
    _get_access_token,
    _get_account_identity,
    _get_authorization_url,
    _get_email_verified,
    _require_verified_email_evidence,
    _set_state_cookie,
    _validate_state,
    create_oauth_associate_controller,
    create_oauth_controller,
)
from litestar_auth.exceptions import ConfigurationError, ErrorCode, OAuthAccountAlreadyLinkedError
from litestar_auth.oauth.service import OAuthAuthorization

pytestmark = pytest.mark.unit


# --- _validate_state ---


def test_set_state_cookie_uses_expected_cookie_settings() -> None:
    """State-cookie helper writes the hardened OAuth cookie."""
    response = Response(content=None)

    _set_state_cookie(
        response,
        cookie_name="__oauth_state_github",
        state="secure-state",
        cookie_path="/auth/oauth/github",
        cookie_secure=True,
    )

    cookie = response.cookies[0]
    assert cookie.key == "__oauth_state_github"
    assert cookie.value == "secure-state"
    assert cookie.max_age == STATE_COOKIE_MAX_AGE
    assert cookie.path == "/auth/oauth/github"
    assert cookie.secure is True
    assert cookie.httponly is True
    assert cookie.samesite == "lax"


def test_clear_state_cookie_uses_expected_cookie_settings() -> None:
    """State-cookie clear helper expires the same hardened OAuth cookie."""
    response = Response(content=None)

    _clear_state_cookie(
        response,
        cookie_name="__oauth_state_github",
        cookie_path="/auth/oauth/github",
        cookie_secure=False,
    )

    cookie = response.cookies[0]
    assert cookie.key == "__oauth_state_github"
    assert not cookie.value
    assert cookie.max_age == 0
    assert cookie.path == "/auth/oauth/github"
    assert cookie.secure is False
    assert cookie.httponly is True
    assert cookie.samesite == "lax"


def test_validate_state_passes_when_cookie_matches_query() -> None:
    """Matching cookie and query state does not raise."""
    state = "same-secure-state"
    _validate_state(state, state)


def test_validate_state_raises_when_cookie_missing() -> None:
    """None cookie_state raises ClientException 400 with OAUTH_STATE_INVALID."""
    with pytest.raises(ClientException) as exc_info:
        _validate_state(None, "query-state")
    assert exc_info.value.status_code == HTTP_400_BAD_REQUEST
    extra = exc_info.value.extra
    assert (extra.get("code") if isinstance(extra, dict) else None) == ErrorCode.OAUTH_STATE_INVALID
    assert "Invalid OAuth state" in exc_info.value.detail


def test_validate_state_raises_when_mismatch() -> None:
    """Mismatched cookie and query state raises ClientException 400."""
    with pytest.raises(ClientException) as exc_info:
        _validate_state("cookie-state", "query-state")
    assert exc_info.value.status_code == HTTP_400_BAD_REQUEST
    extra = exc_info.value.extra
    assert (extra.get("code") if isinstance(extra, dict) else None) == ErrorCode.OAUTH_STATE_INVALID


# --- _get_authorization_url ---


async def test_get_authorization_url_raises_when_client_lacks_method() -> None:
    """Client without get_authorization_url raises ConfigurationError."""
    client = object()
    with pytest.raises(ConfigurationError) as exc_info:
        await _get_authorization_url(
            oauth_client=client,
            redirect_uri="https://app.example/callback",
            state="state",
        )
    assert "get_authorization_url" in str(exc_info.value)


async def test_get_authorization_url_raises_when_return_not_string() -> None:
    """Client returning non-string URL raises ConfigurationError."""
    client = MagicMock()
    client.get_authorization_url = AsyncMock(return_value=123)
    with pytest.raises(ConfigurationError) as exc_info:
        await _get_authorization_url(
            oauth_client=client,
            redirect_uri="https://app.example/callback",
            state="state",
        )
    assert "invalid authorization url" in str(exc_info.value).lower()


async def test_get_authorization_url_raises_when_return_empty_string() -> None:
    """Client returning empty string raises ConfigurationError."""
    client = MagicMock()
    client.get_authorization_url = AsyncMock(return_value="")
    with pytest.raises(ConfigurationError) as exc_info:
        await _get_authorization_url(
            oauth_client=client,
            redirect_uri="https://app.example/callback",
            state="state",
        )
    assert "invalid authorization url" in str(exc_info.value).lower()


async def test_get_authorization_url_success_without_scopes() -> None:
    """Valid client returns URL and calls get_authorization_url(redirect_uri, state)."""
    client = MagicMock()
    client.get_authorization_url = AsyncMock(return_value="https://provider.example/authorize?state=state")
    url = await _get_authorization_url(
        oauth_client=client,
        redirect_uri="https://app.example/callback",
        state="state",
    )
    assert url == "https://provider.example/authorize?state=state"
    client.get_authorization_url.assert_called_once_with("https://app.example/callback", "state")


async def test_get_authorization_url_success_with_scopes() -> None:
    """With scopes list, scope string is joined and passed as scope=."""
    client = MagicMock()
    client.get_authorization_url = AsyncMock(return_value="https://provider.example/authorize")
    url = await _get_authorization_url(
        oauth_client=client,
        redirect_uri="https://app.example/callback",
        state="state",
        scopes=["openid", "email"],
    )
    assert url == "https://provider.example/authorize"
    client.get_authorization_url.assert_called_once_with(
        "https://app.example/callback",
        "state",
        scope="openid email",
    )


# --- _get_access_token ---


async def test_get_access_token_raises_when_client_lacks_method() -> None:
    """Client without get_access_token raises ConfigurationError."""
    client = object()
    with pytest.raises(ConfigurationError) as exc_info:
        await _get_access_token(oauth_client=client, code="code", redirect_uri="https://app.example/callback")
    assert "get_access_token" in str(exc_info.value)


async def test_get_access_token_raises_when_payload_missing_access_token() -> None:
    """Payload without access_token raises ConfigurationError."""
    client = MagicMock()
    client.get_access_token = AsyncMock(return_value={})
    with pytest.raises(ConfigurationError) as exc_info:
        await _get_access_token(oauth_client=client, code="code", redirect_uri="https://app.example/callback")
    assert "access_token" in str(exc_info.value).lower()


async def test_get_access_token_raises_when_access_token_empty() -> None:
    """Payload with empty access_token raises ConfigurationError."""
    client = MagicMock()
    client.get_access_token = AsyncMock(return_value={"access_token": ""})
    with pytest.raises(ConfigurationError) as exc_info:
        await _get_access_token(oauth_client=client, code="code", redirect_uri="https://app.example/callback")
    assert "access_token" in str(exc_info.value).lower()


async def test_get_access_token_raises_when_expires_at_not_int() -> None:
    """Payload with non-int expires_at raises ConfigurationError."""
    client = MagicMock()
    client.get_access_token = AsyncMock(
        return_value={"access_token": "at", "expires_at": "not-an-int", "refresh_token": None},
    )
    with pytest.raises(ConfigurationError) as exc_info:
        await _get_access_token(oauth_client=client, code="code", redirect_uri="https://app.example/callback")
    assert "expires_at" in str(exc_info.value).lower()


async def test_get_access_token_raises_when_refresh_token_not_str() -> None:
    """Payload with non-str refresh_token raises ConfigurationError."""
    client = MagicMock()
    client.get_access_token = AsyncMock(
        return_value={"access_token": "at", "expires_at": 3600, "refresh_token": 123},
    )
    with pytest.raises(ConfigurationError) as exc_info:
        await _get_access_token(oauth_client=client, code="code", redirect_uri="https://app.example/callback")
    assert "refresh_token" in str(exc_info.value).lower()


async def test_get_access_token_success_with_mapping() -> None:
    """Valid mapping payload returns normalized OAuthTokenPayload."""
    client = MagicMock()
    client.get_access_token = AsyncMock(
        return_value={"access_token": "at", "expires_at": 3600, "refresh_token": "rt"},
    )
    payload = await _get_access_token(oauth_client=client, code="code", redirect_uri="https://app.example/callback")
    assert payload["access_token"] == "at"
    assert payload["expires_at"] == 3600  # noqa: PLR2004
    assert payload["refresh_token"] == "rt"


async def test_get_access_token_success_with_none_expires_and_refresh() -> None:
    """Payload with None expires_at and refresh_token is valid."""
    client = MagicMock()
    client.get_access_token = AsyncMock(return_value={"access_token": "at"})
    payload = await _get_access_token(oauth_client=client, code="code", redirect_uri="https://app.example/callback")
    assert payload["access_token"] == "at"
    assert payload["expires_at"] is None
    assert payload["refresh_token"] is None


async def test_get_access_token_success_with_object_dict_payload() -> None:
    """Payload as object with __dict__ (e.g. from vars()) is accepted."""

    class PayloadObj:
        def __init__(self) -> None:
            self.access_token = "at"
            self.expires_at = None
            self.refresh_token = None

    client = MagicMock()
    client.get_access_token = AsyncMock(return_value=PayloadObj())
    payload = await _get_access_token(oauth_client=client, code="code", redirect_uri="https://app.example/callback")
    assert payload["access_token"] == "at"
    assert payload["expires_at"] is None
    assert payload["refresh_token"] is None


# --- _get_account_identity ---


async def test_get_account_identity_success_via_get_id_email() -> None:
    """get_id_email returning valid (id, email) tuple succeeds."""
    client = MagicMock()
    client.get_id_email = AsyncMock(return_value=("provider-id-123", "user@example.com"))
    account_id, account_email = await _get_account_identity(client, "access-token")
    assert account_id == "provider-id-123"
    assert account_email == "user@example.com"


async def test_get_account_identity_raises_when_get_id_email_bad_tuple_length() -> None:
    """get_id_email returning wrong-length tuple raises ConfigurationError."""
    client = MagicMock()
    client.get_id_email = AsyncMock(return_value=("only-one",))
    with pytest.raises(ConfigurationError) as exc_info:
        await _get_account_identity(client, "access-token")
    assert "invalid account identity" in str(exc_info.value).lower()


async def test_get_account_identity_raises_when_get_id_email_not_tuple() -> None:
    """get_id_email returning non-tuple raises ConfigurationError."""
    client = MagicMock()
    client.get_id_email = AsyncMock(return_value=["id", "email"])
    with pytest.raises(ConfigurationError) as exc_info:
        await _get_account_identity(client, "access-token")
    assert "invalid account identity" in str(exc_info.value).lower()


async def test_get_account_identity_raises_when_get_id_email_empty_strings() -> None:
    """get_id_email returning (id, email) with empty string raises ConfigurationError."""
    client = MagicMock()
    client.get_id_email = AsyncMock(return_value=("", "user@example.com"))
    with pytest.raises(ConfigurationError) as exc_info:
        await _get_account_identity(client, "access-token")
    assert "invalid account identity" in str(exc_info.value).lower()


async def test_get_account_identity_raises_when_missing_both_methods() -> None:
    """Client with neither get_id_email nor get_profile raises ConfigurationError."""
    client = object()
    with pytest.raises(ConfigurationError) as exc_info:
        await _get_account_identity(client, "access-token")
    assert "get_id_email" in str(exc_info.value) or "get_profile" in str(exc_info.value)


async def test_get_account_identity_raises_when_profile_missing_account_id() -> None:
    """get_profile path with no account_id/id raises ConfigurationError."""
    client = MagicMock()
    client.get_id_email = None
    client.get_profile = AsyncMock(return_value={"email": "user@example.com"})
    with pytest.raises(ConfigurationError) as exc_info:
        await _get_account_identity(client, "access-token")
    assert "account id" in str(exc_info.value).lower()


async def test_get_account_identity_raises_when_profile_missing_email() -> None:
    """get_profile path with no email raises ClientException OAUTH_NOT_AVAILABLE_EMAIL."""
    client = MagicMock()
    client.get_id_email = None
    client.get_profile = AsyncMock(return_value={"id": "provider-id", "account_id": "provider-id"})
    with pytest.raises(ClientException) as exc_info:
        await _get_account_identity(client, "access-token")
    assert exc_info.value.status_code == HTTP_400_BAD_REQUEST
    extra = exc_info.value.extra
    assert (extra.get("code") if isinstance(extra, dict) else None) == ErrorCode.OAUTH_NOT_AVAILABLE_EMAIL
    assert "email" in exc_info.value.detail.lower()


async def test_get_account_identity_success_via_get_profile() -> None:
    """get_profile returning mapping with id and email succeeds."""
    client = MagicMock()
    client.get_id_email = None
    client.get_profile = AsyncMock(return_value={"id": "provider-id", "email": "user@example.com"})
    account_id, account_email = await _get_account_identity(client, "access-token")
    assert account_id == "provider-id"
    assert account_email == "user@example.com"


async def test_get_account_identity_success_via_get_profile_account_id_email_keys() -> None:
    """get_profile with account_id and account_email keys succeeds."""
    client = MagicMock()
    client.get_id_email = None
    client.get_profile = AsyncMock(
        return_value={"account_id": "pid", "account_email": "u@example.com"},
    )
    account_id, account_email = await _get_account_identity(client, "access-token")
    assert account_id == "pid"
    assert account_email == "u@example.com"


# --- _get_email_verified ---


async def test_get_email_verified_returns_none_when_client_has_no_methods() -> None:
    """Client without get_email_verified and get_profile yields None."""
    client = object()
    assert await _get_email_verified(client, "token") is None


@pytest.mark.parametrize("verified", [True, False])
async def test_get_email_verified_returns_boolean_from_helper(verified: object) -> None:
    """Boolean helper responses are returned directly."""
    client = MagicMock()
    client.get_email_verified = AsyncMock(return_value=verified)
    assert await _get_email_verified(client, "token") is verified


async def test_get_email_verified_reads_boolean_from_get_profile() -> None:
    """get_profile email_verified bool is returned."""
    client = MagicMock()
    client.get_email_verified = None
    client.get_profile = AsyncMock(return_value={"id": "pid", "email": "u@example.com", "email_verified": True})
    assert await _get_email_verified(client, "token") is True


async def test_get_email_verified_returns_none_when_profile_missing_claim() -> None:
    """Missing email_verified claim yields None."""
    client = MagicMock()
    client.get_email_verified = None
    client.get_profile = AsyncMock(return_value={"id": "pid", "email": "u@example.com"})
    assert await _get_email_verified(client, "token") is None


async def test_get_email_verified_parses_string_true_false() -> None:
    """String email_verified values are normalized."""
    client = MagicMock()
    client.get_email_verified = None
    client.get_profile = AsyncMock(return_value={"id": "pid", "email": "u@example.com", "email_verified": " true "})
    assert await _get_email_verified(client, "token") is True
    client.get_profile = AsyncMock(return_value={"id": "pid", "email": "u@example.com", "email_verified": "false"})
    assert await _get_email_verified(client, "token") is False


async def test_get_email_verified_raises_on_invalid_profile_value() -> None:
    """Invalid email_verified values from get_profile raise ConfigurationError."""
    client = MagicMock()
    client.get_email_verified = None
    client.get_profile = AsyncMock(return_value={"id": "pid", "email": "u@example.com", "email_verified": 123})
    with pytest.raises(ConfigurationError, match=r"email_verified"):
        await _get_email_verified(client, "token")


@pytest.mark.parametrize("verified", [True, False])
async def test_get_email_verified_handles_sync_helper(verified: object) -> None:
    """Synchronous boolean returns from get_email_verified() are honoured."""
    client = MagicMock()
    client.get_email_verified = MagicMock(return_value=verified)
    assert await _get_email_verified(client, "token") is verified


async def test_get_email_verified_raises_on_invalid_helper_value() -> None:
    """Invalid return values from get_email_verified() raise ConfigurationError."""
    client = MagicMock()
    client.get_email_verified = AsyncMock(return_value="not-a-bool")
    with pytest.raises(ConfigurationError, match=r"verification"):
        await _get_email_verified(client, "token")


async def test_require_account_state_calls_optional_validator() -> None:
    """Account-state validation delegates only when the manager exposes a callable hook."""

    class _User:
        id = "user-id"
        email = "user@example.com"
        is_active = True
        is_verified = True
        is_superuser = False

    class _Manager:
        def __init__(self) -> None:
            self.calls: list[tuple[object, bool]] = []

        def require_account_state(self, user: object, *, require_verified: bool) -> None:
            self.calls.append((user, require_verified))

    manager = _Manager()
    user = _User()

    await _require_account_state(cast("Any", user), user_manager=cast("Any", manager), require_verified=False)

    assert manager.calls == [(user, False)]


async def test_require_account_state_ignores_non_callable_validator() -> None:
    """A non-callable account-state attribute is treated as absent."""

    class _User:
        id = "user-id"
        email = "user@example.com"
        is_active = True
        is_verified = True
        is_superuser = False

    class _Manager:
        require_account_state = "not-callable"

    await _require_account_state(cast("Any", _User()), user_manager=cast("Any", _Manager()), require_verified=True)


def test_require_verified_email_evidence_accepts_true() -> None:
    """Verified provider evidence passes without raising."""
    _require_verified_email_evidence(email_verified=True)


@pytest.mark.parametrize("email_verified", [False, None])
def test_require_verified_email_evidence_rejects_false_or_absent(email_verified: object) -> None:
    """Missing/false provider verification evidence raises OAuth email-not-verified client error."""
    with pytest.raises(ClientException) as exc_info:
        _require_verified_email_evidence(email_verified=cast("bool | None", email_verified))
    assert exc_info.value.status_code == HTTP_400_BAD_REQUEST
    extra = exc_info.value.extra
    assert (extra.get("code") if isinstance(extra, dict) else None) == ErrorCode.OAUTH_EMAIL_NOT_VERIFIED


def _build_associate_controller(*, user_manager: object | None = None) -> object:
    """Create an OAuth associate controller instance for direct handler tests.

    Returns:
        Instantiated provider-scoped associate controller.
    """
    controller_class = create_oauth_associate_controller(
        provider_name="github",
        user_manager=cast("Any", user_manager or MagicMock()),
        oauth_client=object(),
        redirect_base_url="https://app.example/auth/associate",
        path="/auth/associate",
        cookie_secure=True,
    )
    return cast("Any", controller_class(owner=Router(path="/", route_handlers=[])))


def _build_login_controller(*, backend: object, user_manager: object) -> object:
    """Create an OAuth login controller instance for direct handler tests.

    Returns:
        Instantiated provider-scoped login controller.
    """
    controller_class = create_oauth_controller(
        provider_name="github",
        backend=cast("Any", backend),
        user_manager=cast("Any", user_manager),
        oauth_client=object(),
        redirect_base_url="https://app.example/auth/oauth",
        path="/auth/oauth",
        cookie_secure=True,
    )
    return cast("Any", controller_class(owner=Router(path="/", route_handlers=[])))


def test_oauth_module_reload_preserves_public_helpers() -> None:
    """Reloading the module under coverage preserves the exported helper surface."""
    reloaded = importlib.reload(oauth_module)

    assert reloaded.STATE_COOKIE_MAX_AGE == STATE_COOKIE_MAX_AGE
    assert reloaded._build_callback_url_from_base("https://app.example/auth", "github") == (
        "https://app.example/auth/github/callback"
    )


async def test_oauth_associate_authorize_sets_state_cookie_and_redirects(monkeypatch: pytest.MonkeyPatch) -> None:
    """Associate authorize returns the provider redirect and sets the provider-scoped state cookie."""
    seen: dict[str, object] = {}

    async def fake_authorize(
        self: object,
        *,
        redirect_uri: str,
        scopes: list[str] | None = None,
    ) -> OAuthAuthorization:
        del self
        await asyncio.sleep(0)
        seen["redirect_uri"] = redirect_uri
        seen["scopes"] = scopes
        return OAuthAuthorization(
            authorization_url="https://provider.example/authorize?state=associate-state",
            state="associate-state",
        )

    monkeypatch.setattr("litestar_auth.controllers.oauth.OAuthService.authorize", fake_authorize)
    controller = cast("Any", _build_associate_controller())

    response = await controller.authorize.fn(controller, cast("Any", SimpleNamespace(cookies={}, user=object())))

    assert isinstance(response, Redirect)
    assert response.url == "https://provider.example/authorize?state=associate-state"
    assert seen == {"redirect_uri": "https://app.example/auth/associate/github/callback", "scopes": None}
    cookie = response.cookies[0]
    assert cookie.key == "__oauth_associate_state_github"
    assert cookie.value == "associate-state"
    assert cookie.max_age == STATE_COOKIE_MAX_AGE
    assert cookie.path == "/auth/associate/github"
    assert cookie.secure is True
    assert cookie.httponly is True
    assert cookie.samesite == "lax"


def test_create_oauth_associate_controller_requires_exactly_one_manager_input() -> None:
    """Associate controller factory rejects missing and duplicate manager wiring."""
    with pytest.raises(ConfigurationError, match="exactly one"):
        create_oauth_associate_controller(
            provider_name="github",
            oauth_client=object(),
            redirect_base_url="https://app.example/auth/associate",
        )

    with pytest.raises(ConfigurationError, match="exactly one"):
        create_oauth_associate_controller(
            provider_name="github",
            user_manager=cast("Any", MagicMock()),
            user_manager_dependency_key="litestar_auth_oauth_associate_user_manager",
            oauth_client=object(),
            redirect_base_url="https://app.example/auth/associate",
        )


async def test_oauth_associate_callback_links_authenticated_user_and_clears_cookie(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Associate callback validates state, links the current user, and expires the state cookie."""
    user = object()
    manager = MagicMock()
    seen: dict[str, object] = {}

    async def fake_associate_account(
        self: object,
        *,
        user: object,
        code: str,
        redirect_uri: str,
        user_manager: object,
    ) -> None:
        del self
        await asyncio.sleep(0)
        seen["user"] = user
        seen["code"] = code
        seen["redirect_uri"] = redirect_uri
        seen["user_manager"] = user_manager

    monkeypatch.setattr("litestar_auth.controllers.oauth.OAuthService.associate_account", fake_associate_account)
    controller = cast("Any", _build_associate_controller(user_manager=manager))
    request = cast(
        "Any",
        SimpleNamespace(cookies={"__oauth_associate_state_github": "associate-state"}, user=user),
    )

    response = await controller.callback.fn(
        controller,
        request,
        code="provider-code",
        oauth_state="associate-state",
    )

    assert response.content == {"linked": True}
    assert seen == {
        "user": user,
        "code": "provider-code",
        "redirect_uri": "https://app.example/auth/associate/github/callback",
        "user_manager": manager,
    }
    cookie = response.cookies[0]
    assert cookie.key == "__oauth_associate_state_github"
    assert not cookie.value
    assert cookie.max_age == 0
    assert cookie.path == "/auth/associate/github"
    assert cookie.secure is True
    assert cookie.httponly is True
    assert cookie.samesite == "lax"


async def test_oauth_associate_callback_rejects_invalid_state() -> None:
    """Associate callback fails closed when the callback state does not match the cookie."""
    controller = cast("Any", _build_associate_controller())
    request = cast(
        "Any",
        SimpleNamespace(cookies={"__oauth_associate_state_github": "cookie-state"}, user=object()),
    )

    with pytest.raises(ClientException) as exc_info:
        await controller.callback.fn(controller, request, code="provider-code", oauth_state="query-state")

    assert exc_info.value.status_code == HTTP_400_BAD_REQUEST
    extra = exc_info.value.extra
    assert (extra.get("code") if isinstance(extra, dict) else None) == ErrorCode.OAUTH_STATE_INVALID


async def test_oauth_associate_callback_propagates_already_linked_error(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Associate callback preserves the stable linked-account error from the service layer."""

    async def fail_associate_account(
        self: object,
        *,
        user: object,
        code: str,
        redirect_uri: str,
        user_manager: object,
    ) -> None:
        del self, user, code, redirect_uri, user_manager
        await asyncio.sleep(0)
        raise OAuthAccountAlreadyLinkedError

    monkeypatch.setattr("litestar_auth.controllers.oauth.OAuthService.associate_account", fail_associate_account)
    controller = cast("Any", _build_associate_controller())
    request = cast(
        "Any",
        SimpleNamespace(cookies={"__oauth_associate_state_github": "associate-state"}, user=object()),
    )

    with pytest.raises(OAuthAccountAlreadyLinkedError) as exc_info:
        await controller.callback.fn(controller, request, code="provider-code", oauth_state="associate-state")

    assert exc_info.value.code == ErrorCode.OAUTH_ACCOUNT_ALREADY_LINKED


async def test_oauth_associate_di_callback_uses_injected_manager(monkeypatch: pytest.MonkeyPatch) -> None:
    """DI-key associate callback passes the injected manager through to the service layer."""
    injected_manager = MagicMock()
    seen: dict[str, object] = {}

    async def fake_associate_account(
        self: object,
        *,
        user: object,
        code: str,
        redirect_uri: str,
        user_manager: object,
    ) -> None:
        del self, user, code, redirect_uri
        await asyncio.sleep(0)
        seen["user_manager"] = user_manager

    monkeypatch.setattr("litestar_auth.controllers.oauth.OAuthService.associate_account", fake_associate_account)
    controller_class = create_oauth_associate_controller(
        provider_name="github",
        user_manager_dependency_key="litestar_auth_oauth_associate_user_manager",
        oauth_client=object(),
        redirect_base_url="https://app.example/auth/associate",
        path="/auth/associate",
        cookie_secure=True,
    )
    controller = cast("Any", controller_class(owner=Router(path="/", route_handlers=[])))
    request = cast(
        "Any",
        SimpleNamespace(cookies={"__oauth_associate_state_github": "associate-state"}, user=object()),
    )

    await controller.callback.fn(
        controller,
        request,
        code="provider-code",
        oauth_state="associate-state",
        litestar_auth_oauth_associate_user_manager=injected_manager,
    )

    assert seen == {"user_manager": injected_manager}


async def test_oauth_login_authorize_sets_state_cookie_and_redirects(monkeypatch: pytest.MonkeyPatch) -> None:
    """Login authorize forwards scopes, provider callback URL, and the OAuth state cookie."""
    seen: dict[str, object] = {}

    async def fake_authorize(
        self: object,
        *,
        redirect_uri: str,
        scopes: list[str] | None = None,
    ) -> OAuthAuthorization:
        del self
        await asyncio.sleep(0)
        seen["redirect_uri"] = redirect_uri
        seen["scopes"] = scopes
        return OAuthAuthorization(
            authorization_url="https://provider.example/authorize?state=login-state",
            state="login-state",
        )

    monkeypatch.setattr("litestar_auth.controllers.oauth.OAuthService.authorize", fake_authorize)
    controller = cast("Any", _build_login_controller(backend=MagicMock(), user_manager=MagicMock()))

    response = await controller.authorize.fn(
        controller,
        cast("Any", SimpleNamespace(cookies={}, user=None)),
        scopes=["openid", "email"],
    )

    assert isinstance(response, Redirect)
    assert response.url == "https://provider.example/authorize?state=login-state"
    assert seen == {
        "redirect_uri": "https://app.example/auth/oauth/github/callback",
        "scopes": ["openid", "email"],
    }
    cookie = response.cookies[0]
    assert cookie.key == "__oauth_state_github"
    assert cookie.value == "login-state"
    assert cookie.path == "/auth/oauth/github"


async def test_oauth_login_callback_logs_in_and_clears_state_cookie(monkeypatch: pytest.MonkeyPatch) -> None:
    """Login callback validates state, resolves the user, logs in, and clears the state cookie."""
    user = object()
    manager = MagicMock()
    manager.on_after_login = AsyncMock()
    backend = MagicMock()
    backend.login = AsyncMock(return_value=Response(content={"access_token": "local-token"}))
    seen: dict[str, object] = {}

    async def fake_complete_login(
        self: object,
        *,
        code: str,
        redirect_uri: str,
        user_manager: object,
    ) -> object:
        del self
        await asyncio.sleep(0)
        seen["code"] = code
        seen["redirect_uri"] = redirect_uri
        seen["user_manager"] = user_manager
        return user

    monkeypatch.setattr("litestar_auth.controllers.oauth.OAuthService.complete_login", fake_complete_login)
    controller = cast("Any", _build_login_controller(backend=backend, user_manager=manager))
    request = cast("Any", SimpleNamespace(cookies={"__oauth_state_github": "login-state"}, user=None))

    response = await controller.callback.fn(controller, request, code="provider-code", oauth_state="login-state")

    assert response.content == {"access_token": "local-token"}
    assert seen == {
        "code": "provider-code",
        "redirect_uri": "https://app.example/auth/oauth/github/callback",
        "user_manager": manager,
    }
    backend.login.assert_awaited_once_with(user)
    manager.on_after_login.assert_awaited_once_with(user)
    cookie = response.cookies[0]
    assert cookie.key == "__oauth_state_github"
    assert cookie.max_age == 0
    assert cookie.path == "/auth/oauth/github"


async def test_oauth_login_callback_rejects_invalid_state() -> None:
    """Login callback fails closed before invoking the OAuth service on state mismatch."""
    manager = MagicMock()
    manager.on_after_login = AsyncMock()
    backend = MagicMock()
    backend.login = AsyncMock()
    controller = cast("Any", _build_login_controller(backend=backend, user_manager=manager))
    request = cast("Any", SimpleNamespace(cookies={"__oauth_state_github": "cookie-state"}, user=None))

    with pytest.raises(ClientException) as exc_info:
        await controller.callback.fn(controller, request, code="provider-code", oauth_state="query-state")

    assert exc_info.value.status_code == HTTP_400_BAD_REQUEST
    backend.login.assert_not_called()
    manager.on_after_login.assert_not_called()
