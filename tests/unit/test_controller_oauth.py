"""Unit tests for OAuth controller helpers and factory wiring."""

from __future__ import annotations

import asyncio
import inspect
from pathlib import Path
from types import SimpleNamespace
from typing import Any, cast
from unittest.mock import AsyncMock, MagicMock

import pytest
from litestar import Litestar, Router
from litestar.exceptions import ClientException
from litestar.openapi.config import OpenAPIConfig
from litestar.response import Response
from litestar.response.redirect import Redirect
from litestar.status_codes import HTTP_400_BAD_REQUEST

import litestar_auth.controllers._utils as controller_utils_module
import litestar_auth.controllers.oauth as oauth_module
from litestar_auth.controllers._utils import _require_account_state
from litestar_auth.controllers.oauth import (
    STATE_COOKIE_MAX_AGE,
    _clear_state_cookie,
    _require_verified_email_evidence,
    _set_state_cookie,
    _validate_state,
    create_oauth_associate_controller,
    create_oauth_controller,
)
from litestar_auth.exceptions import (
    ConfigurationError,
    ErrorCode,
    InactiveUserError,
    OAuthAccountAlreadyLinkedError,
)
from litestar_auth.oauth.service import OAuthAuthorization
from tests.unit.test_definition_file_coverage import load_reloaded_test_alias

pytestmark = pytest.mark.unit

REMOVED_OAUTH_CONTROLLER_ADAPTER_PASSTHROUGH_HELPERS = (
    "_get_authorization_url",
    "_get_access_token",
    "_get_account_identity",
    "_get_email_verified",
    "_as_mapping",
)


def _make_oauth_client() -> oauth_module.OAuthClientProtocol:
    """Return a typed OAuth client placeholder for controller tests."""
    return cast("oauth_module.OAuthClientProtocol", object())


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


def test_manual_oauth_factories_expose_typed_client_annotations() -> None:
    """Manual controller factories advertise the explicit OAuth client protocol."""
    assert create_oauth_controller.__annotations__["oauth_client"] == "OAuthClientProtocol"
    assert create_oauth_associate_controller.__annotations__["oauth_client"] == "OAuthClientProtocol"


def test_oauth_module_does_not_expose_removed_adapter_passthrough_helpers() -> None:
    """Removed controller-to-adapter passthrough helpers stay absent from the module surface."""
    module_members = vars(oauth_module)

    for helper_name in REMOVED_OAUTH_CONTROLLER_ADAPTER_PASSTHROUGH_HELPERS:
        assert helper_name not in module_members
        assert not hasattr(oauth_module, helper_name)


def test_create_oauth_controller_builds_the_shared_client_adapter_before_assembly(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Manual login controller wiring resolves the direct client through the shared adapter builder."""
    oauth_client = _make_oauth_client()
    oauth_client_adapter = MagicMock()
    backend = cast("Any", MagicMock())
    user_manager = cast("Any", MagicMock())
    controller = cast("type[Any]", object())
    build_adapter = MagicMock(return_value=oauth_client_adapter)
    create_controller = MagicMock(return_value=controller)
    monkeypatch.setattr(oauth_module, "_build_oauth_client_adapter", build_adapter)
    monkeypatch.setattr(oauth_module, "_create_login_oauth_controller", create_controller)

    created_controller = create_oauth_controller(
        provider_name="github",
        backend=backend,
        user_manager=user_manager,
        oauth_client=oauth_client,
        redirect_base_url="https://app.example/auth/oauth",
    )

    assert created_controller is controller
    build_adapter.assert_called_once_with(oauth_client=oauth_client)
    create_controller.assert_called_once_with(
        provider_name="github",
        backend=backend,
        user_manager=user_manager,
        oauth_client_adapter=oauth_client_adapter,
        redirect_base_url="https://app.example/auth/oauth",
        path="/auth/oauth",
        cookie_secure=True,
        oauth_scopes=None,
        associate_by_email=False,
        trust_provider_email_verified=False,
    )


async def test_require_account_state_calls_optional_validator() -> None:
    """Account-state validation delegates only when the manager exposes a callable hook."""

    class _User:
        id = "user-id"
        email = "user@example.com"
        is_active = True
        is_verified = True

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
        oauth_client=_make_oauth_client(),
        redirect_base_url="https://app.example/auth/associate",
        path="/auth/associate",
        cookie_secure=True,
    )
    return cast("Any", controller_class(owner=Router(path="/", route_handlers=[])))


def _build_login_controller(
    *,
    backend: object,
    user_manager: object,
    oauth_scopes: tuple[str, ...] | None = None,
) -> object:
    """Create an OAuth login controller instance for direct handler tests.

    Returns:
        Instantiated provider-scoped login controller.
    """
    controller_class = create_oauth_controller(
        provider_name="github",
        backend=cast("Any", backend),
        user_manager=cast("Any", user_manager),
        oauth_client=_make_oauth_client(),
        redirect_base_url="https://app.example/auth/oauth",
        path="/auth/oauth",
        cookie_secure=True,
        oauth_scopes=oauth_scopes,
    )
    return cast("Any", controller_class(owner=Router(path="/", route_handlers=[])))


async def test_controller_helper_module_reload_preserves_account_state_error_contract(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Reload coverage keeps controller helper error mapping stable for callers."""
    assert controller_utils_module.__file__ is not None
    reloaded_module = load_reloaded_test_alias(
        alias_name="_coverage_alias_controller_utils",
        source_path=Path(controller_utils_module.__file__),
        monkeypatch=monkeypatch,
    )
    manager = MagicMock()
    manager.require_account_state.side_effect = reloaded_module.InactiveUserError()

    with pytest.raises(ClientException) as exc_info:
        await reloaded_module._require_account_state(object(), user_manager=manager)

    extra = exc_info.value.extra
    assert (extra.get("code") if isinstance(extra, dict) else None) == ErrorCode.LOGIN_USER_INACTIVE
    assert exc_info.value.detail == reloaded_module.InactiveUserError.default_message


def test_oauth_module_reload_preserves_helper_error_contract(monkeypatch: pytest.MonkeyPatch) -> None:
    """Reloading the controller module preserves public helper behavior, not exception identity."""
    assert oauth_module.__file__ is not None
    reloaded = load_reloaded_test_alias(
        alias_name="_coverage_alias_controller_oauth",
        source_path=Path(oauth_module.__file__).resolve(),
        monkeypatch=monkeypatch,
    )

    assert reloaded.STATE_COOKIE_MAX_AGE == STATE_COOKIE_MAX_AGE
    assert reloaded._build_callback_url_from_base("https://app.example/auth", "github") == (
        "https://app.example/auth/github/callback"
    )

    with pytest.raises(ClientException) as client_exc_info:
        reloaded._validate_state("cookie-state", "query-state")

    with pytest.raises(Exception, match="valid Python identifier") as config_exc_info:
        reloaded.create_oauth_associate_controller(
            provider_name="github",
            user_manager_dependency_key="not-a-valid-identifier",
            oauth_client=_make_oauth_client(),
            redirect_base_url="https://app.example/auth/associate",
        )

    extra = client_exc_info.value.extra
    assert (extra.get("code") if isinstance(extra, dict) else None) == ErrorCode.OAUTH_STATE_INVALID
    assert type(config_exc_info.value).__name__ == "ConfigurationError"
    assert getattr(config_exc_info.value, "code", None) == ErrorCode.CONFIGURATION_INVALID


def test_shared_oauth_controller_assembly_uses_direct_manager_binding_and_provider_scoped_paths() -> None:
    """Shared assembly keeps login controllers on the direct-manager provider-scoped contract."""
    manager = MagicMock()

    assembly = oauth_module._build_oauth_controller_assembly(
        provider_name="github",
        oauth_client_adapter=oauth_module._build_oauth_client_adapter(oauth_client=_make_oauth_client()),
        redirect_base_url="https://app.example/auth/oauth",
        path="/auth/oauth",
        cookie_secure=True,
        state_cookie_prefix=oauth_module.STATE_COOKIE_PREFIX,
        controller_name_suffix="OAuthController",
        user_manager_binding=oauth_module._build_direct_user_manager_binding(cast("Any", manager)),
        oauth_scopes=("openid", "email", "openid"),
        associate_by_email=True,
        trust_provider_email_verified=True,
    )

    assert assembly.controller_name == "GithubOAuthController"
    assert assembly.controller_path == "/auth/oauth/github"
    assert assembly.callback_url == "https://app.example/auth/oauth/github/callback"
    assert assembly.cookie_name == "__oauth_state_github"
    assert assembly.cookie_path == "/auth/oauth/github"
    assert assembly.cookie_secure is True
    assert assembly.oauth_scopes == ("openid", "email")
    assert assembly.user_manager_binding.user_manager is manager
    assert assembly.user_manager_binding.dependency_parameter_name is None


def test_shared_oauth_controller_assembly_rejects_missing_client_inputs() -> None:
    """Internal controller assembly requires either a raw client or a resolved adapter."""
    with pytest.raises(ValueError, match="Provide oauth_client or oauth_client_adapter"):
        oauth_module._build_oauth_controller_assembly(
            provider_name="github",
            redirect_base_url="https://app.example/auth/oauth",
            path="/auth/oauth",
            cookie_secure=True,
            state_cookie_prefix=oauth_module.STATE_COOKIE_PREFIX,
            controller_name_suffix="OAuthController",
            user_manager_binding=oauth_module._build_direct_user_manager_binding(cast("Any", MagicMock())),
            validate_redirect_base_url=False,
        )


def test_shared_oauth_controller_assembly_rejects_duplicate_client_inputs() -> None:
    """Internal controller assembly fails closed when both raw and adapted clients are supplied."""
    with pytest.raises(ValueError, match="Provide only one of oauth_client or oauth_client_adapter"):
        oauth_module._build_oauth_controller_assembly(
            provider_name="github",
            oauth_client=_make_oauth_client(),
            oauth_client_adapter=oauth_module._build_oauth_client_adapter(oauth_client=_make_oauth_client()),
            redirect_base_url="https://app.example/auth/oauth",
            path="/auth/oauth",
            cookie_secure=True,
            state_cookie_prefix=oauth_module.STATE_COOKIE_PREFIX,
            controller_name_suffix="OAuthController",
            user_manager_binding=oauth_module._build_direct_user_manager_binding(cast("Any", MagicMock())),
            validate_redirect_base_url=False,
        )


def test_manual_oauth_adapter_builder_requires_loader_for_class_path() -> None:
    """Manual class-path client resolution requires an explicit lazy-loader callback."""
    with pytest.raises(ConfigurationError, match="requires an OAuth client loader"):
        oauth_module._build_oauth_client_adapter(oauth_client_class="tests.fake.Client")


@pytest.mark.parametrize(
    ("oauth_scopes", "expected_message"),
    [
        ([cast("Any", object())], "OAuth scopes must be strings."),
        ([""], "OAuth scopes must be non-empty strings."),
        (["openid email"], "OAuth scopes must be provided as individual tokens without embedded whitespace."),
    ],
)
def test_create_oauth_controller_rejects_invalid_configured_scopes(
    oauth_scopes: list[object],
    expected_message: str,
) -> None:
    """Manual OAuth controllers reject invalid server-owned scope configuration."""
    with pytest.raises(ConfigurationError, match=expected_message):
        create_oauth_controller(
            provider_name="github",
            backend=cast("Any", MagicMock()),
            user_manager=cast("Any", MagicMock()),
            oauth_client=_make_oauth_client(),
            redirect_base_url="https://app.example/auth/oauth",
            oauth_scopes=cast("Any", oauth_scopes),
        )


@pytest.mark.parametrize(
    ("redirect_base_url", "expected_message"),
    [
        ("http://app.example/auth/oauth", "public HTTPS origin"),
        ("https://localhost/auth/oauth", "non-loopback public HTTPS origin"),
        ("https://127.0.0.1/auth/oauth", "non-loopback public HTTPS origin"),
    ],
)
def test_create_oauth_controller_rejects_insecure_redirect_base_url(
    redirect_base_url: str,
    expected_message: str,
) -> None:
    """Manual login-controller wiring fails closed for HTTP and loopback redirect origins."""
    with pytest.raises(ConfigurationError, match=expected_message):
        create_oauth_controller(
            provider_name="github",
            backend=cast("Any", MagicMock()),
            user_manager=cast("Any", MagicMock()),
            oauth_client=_make_oauth_client(),
            redirect_base_url=redirect_base_url,
        )


def test_shared_oauth_controller_assembly_uses_dependency_binding_for_associate_routes() -> None:
    """Shared assembly keeps associate DI bindings on the provider-scoped cookie and callback contract."""
    assembly = oauth_module._build_oauth_controller_assembly(
        provider_name="github",
        oauth_client_adapter=oauth_module._build_oauth_client_adapter(oauth_client=_make_oauth_client()),
        redirect_base_url="https://app.example/auth/associate",
        path="/auth/associate",
        cookie_secure=False,
        state_cookie_prefix=oauth_module.ASSOCIATE_STATE_COOKIE_PREFIX,
        controller_name_suffix="OAuthAssociateController",
        user_manager_binding=oauth_module._build_associate_user_manager_binding(
            user_manager=None,
            user_manager_dependency_key="litestar_auth_oauth_associate_user_manager",
        ),
    )

    assert assembly.controller_name == "GithubOAuthAssociateController"
    assert assembly.controller_path == "/auth/associate/github"
    assert assembly.callback_url == "https://app.example/auth/associate/github/callback"
    assert assembly.cookie_name == "__oauth_associate_state_github"
    assert assembly.cookie_path == "/auth/associate/github"
    assert assembly.cookie_secure is False
    assert assembly.user_manager_binding.user_manager is None
    assert assembly.user_manager_binding.dependency_parameter_name == "litestar_auth_oauth_associate_user_manager"


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
            oauth_client=_make_oauth_client(),
            redirect_base_url="https://app.example/auth/associate",
        )

    with pytest.raises(ConfigurationError, match="exactly one"):
        create_oauth_associate_controller(
            provider_name="github",
            user_manager=cast("Any", MagicMock()),
            user_manager_dependency_key="litestar_auth_oauth_associate_user_manager",
            oauth_client=_make_oauth_client(),
            redirect_base_url="https://app.example/auth/associate",
        )


def test_create_oauth_associate_controller_rejects_invalid_dependency_parameter_name() -> None:
    """Associate controller factory fails fast for invalid DI parameter names."""
    with pytest.raises(ConfigurationError, match="valid Python identifier"):
        create_oauth_associate_controller(
            provider_name="github",
            user_manager_dependency_key="not-a-valid-identifier",
            oauth_client=_make_oauth_client(),
            redirect_base_url="https://app.example/auth/associate",
        )


@pytest.mark.parametrize(
    ("redirect_base_url", "expected_message"),
    [
        ("http://app.example/auth/associate", "public HTTPS origin"),
        ("https://localhost/auth/associate", "non-loopback public HTTPS origin"),
        ("https://[::1]/auth/associate", "non-loopback public HTTPS origin"),
    ],
)
def test_create_oauth_associate_controller_rejects_insecure_redirect_base_url(
    redirect_base_url: str,
    expected_message: str,
) -> None:
    """Manual associate-controller wiring fails closed for HTTP and loopback redirect origins."""
    with pytest.raises(ConfigurationError, match=expected_message):
        create_oauth_associate_controller(
            provider_name="github",
            user_manager=cast("Any", MagicMock()),
            oauth_client=_make_oauth_client(),
            redirect_base_url=redirect_base_url,
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


async def test_oauth_associate_callback_rejects_inactive_user_before_linking(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Associate callback enforces account-state validation before linking an OAuth identity."""
    user = object()
    manager = MagicMock()
    manager.require_account_state.side_effect = InactiveUserError
    associate_account = AsyncMock()

    monkeypatch.setattr("litestar_auth.controllers.oauth.OAuthService.associate_account", associate_account)
    controller = cast("Any", _build_associate_controller(user_manager=manager))
    request = cast(
        "Any",
        SimpleNamespace(cookies={"__oauth_associate_state_github": "associate-state"}, user=user),
    )

    with pytest.raises(ClientException) as exc_info:
        await controller.callback.fn(
            controller,
            request,
            code="provider-code",
            oauth_state="associate-state",
        )

    assert exc_info.value.status_code == HTTP_400_BAD_REQUEST
    extra = exc_info.value.extra
    assert (extra.get("code") if isinstance(extra, dict) else None) == ErrorCode.LOGIN_USER_INACTIVE
    associate_account.assert_not_awaited()


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
        raise OAuthAccountAlreadyLinkedError(
            provider="github",
            account_id="provider-user",
            existing_user_id="existing-user",
        )

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
    dependency_parameter_name = "custom_manager_key"
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
        user_manager_dependency_key=dependency_parameter_name,
        oauth_client=_make_oauth_client(),
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
        **{dependency_parameter_name: injected_manager},
    )

    assert seen == {"user_manager": injected_manager}


async def test_oauth_associate_di_callback_raises_when_injected_manager_missing() -> None:
    """DI-key associate callback fails fast when Litestar does not inject the configured manager."""
    controller_class = create_oauth_associate_controller(
        provider_name="github",
        user_manager_dependency_key="custom_manager_key",
        oauth_client=_make_oauth_client(),
        redirect_base_url="https://app.example/auth/associate",
        path="/auth/associate",
        cookie_secure=True,
    )
    controller = cast("Any", controller_class(owner=Router(path="/", route_handlers=[])))
    request = cast(
        "Any",
        SimpleNamespace(cookies={"__oauth_associate_state_github": "associate-state"}, user=object()),
    )

    with pytest.raises(TypeError, match="custom_manager_key"):
        await controller.callback.fn(
            controller,
            request,
            code="provider-code",
            oauth_state="associate-state",
        )


async def test_oauth_associate_di_callback_rejects_duplicate_injected_manager_input(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """DI-key associate callback fails closed when the manager is supplied twice."""
    dependency_parameter_name = "custom_manager_key"
    associate_account = AsyncMock()
    monkeypatch.setattr("litestar_auth.controllers.oauth.OAuthService.associate_account", associate_account)
    controller_class = create_oauth_associate_controller(
        provider_name="github",
        user_manager_dependency_key=dependency_parameter_name,
        oauth_client=_make_oauth_client(),
        redirect_base_url="https://app.example/auth/associate",
        path="/auth/associate",
        cookie_secure=True,
    )
    controller = cast("Any", controller_class(owner=Router(path="/", route_handlers=[])))
    request = cast(
        "Any",
        SimpleNamespace(cookies={"__oauth_associate_state_github": "associate-state"}, user=object()),
    )
    injected_manager = MagicMock()

    with pytest.raises(TypeError, match=dependency_parameter_name):
        await controller.callback.fn(
            controller,
            request,
            "provider-code",
            injected_manager,
            oauth_state="associate-state",
            **{dependency_parameter_name: injected_manager},
        )

    associate_account.assert_not_awaited()


def test_oauth_associate_di_callback_exposes_configured_dependency_parameter_name() -> None:
    """DI-key associate callbacks expose the configured Litestar dependency parameter name."""
    controller = create_oauth_associate_controller(
        provider_name="github",
        user_manager_dependency_key="custom_manager_key",
        oauth_client=_make_oauth_client(),
        redirect_base_url="https://app.example/auth/associate",
        path="/auth/associate",
        cookie_secure=True,
    )

    callback_handler = cast("Any", controller).callback.fn

    assert "custom_manager_key" in inspect.signature(callback_handler).parameters


def test_create_oauth_associate_controller_applies_openapi_security_to_both_protected_routes() -> None:
    """Manual associate controllers expose matching OpenAPI security on authorize and callback."""
    controller = create_oauth_associate_controller(
        provider_name="github",
        user_manager=cast("Any", MagicMock()),
        oauth_client=_make_oauth_client(),
        redirect_base_url="https://app.example/auth/associate",
        path="/auth/associate",
        security=[{"BearerToken": []}],
    )
    app = Litestar(
        route_handlers=[controller],
        openapi_config=OpenAPIConfig(title="Test", version="1.0.0"),
    )
    paths = cast("Any", app.openapi_schema.paths)

    assert paths["/auth/associate/github/authorize"].get.security == [{"BearerToken": []}]
    assert paths["/auth/associate/github/callback"].get.security == [{"BearerToken": []}]


async def test_oauth_login_authorize_sets_state_cookie_and_redirects(monkeypatch: pytest.MonkeyPatch) -> None:
    """Login authorize forwards only configured scopes, callback URL, and the OAuth state cookie."""
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
    controller = cast(
        "Any",
        _build_login_controller(
            backend=MagicMock(),
            user_manager=MagicMock(),
            oauth_scopes=("openid", "email"),
        ),
    )

    response = await controller.authorize.fn(
        controller,
        cast("Any", SimpleNamespace(cookies={}, query_params={}, user=None)),
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


async def test_oauth_login_authorize_rejects_runtime_scope_override() -> None:
    """Login authorize rejects caller-controlled scope overrides."""
    controller = cast("Any", _build_login_controller(backend=MagicMock(), user_manager=MagicMock()))

    with pytest.raises(ClientException) as exc_info:
        await controller.authorize.fn(
            controller,
            cast("Any", SimpleNamespace(cookies={}, query_params={"scopes": "openid"}, user=None)),
        )

    assert exc_info.value.status_code == HTTP_400_BAD_REQUEST
    assert exc_info.value.detail == "OAuth scopes must be configured on the server."


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
