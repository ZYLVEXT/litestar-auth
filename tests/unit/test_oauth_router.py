"""Unit tests for `litestar_auth.oauth.router`."""

from __future__ import annotations

import importlib
import sys
import types
from typing import TYPE_CHECKING, Any, cast
from unittest.mock import Mock

import pytest

import litestar_auth.oauth.router as router_module
from litestar_auth.authentication.backend import AuthenticationBackend
from litestar_auth.oauth import router
from litestar_auth.oauth.router import create_provider_oauth_controller, load_httpx_oauth_client
from litestar_auth.types import UserProtocol

if TYPE_CHECKING:
    from litestar.connection import ASGIConnection
    from litestar.response import Response

    from litestar_auth.controllers.oauth import OAuthControllerUserManagerProtocol

pytestmark = pytest.mark.unit


class _RouterTestUser(UserProtocol[object]):
    """Minimal user protocol implementation for OAuth router typing tests."""

    id: object


class _RouterTestTransport:
    """Minimal transport stub satisfying ``TransportProtocol``."""

    async def read_token(self, connection: ASGIConnection[Any, Any, Any, Any]) -> str | None:
        """Return no token for tests that only exercise router assembly."""
        del connection
        return None

    def set_login_token(self, response: Response[Any], token: str) -> Response[Any]:
        """Return the response unchanged."""
        del token
        return response

    def set_logout(self, response: Response[Any]) -> Response[Any]:
        """Return the response unchanged."""
        return response


class _RouterTestStrategy:
    """Minimal strategy stub satisfying ``StrategyProtocol``."""

    async def read_token(self, token: str | None, user_manager: object) -> _RouterTestUser | None:
        """Return no user for tests that only exercise router assembly."""
        del token, user_manager
        return None

    async def write_token(self, user: _RouterTestUser) -> str:
        """Return a deterministic token for protocol completeness."""
        del user
        return "token"

    async def destroy_token(self, token: str, user: _RouterTestUser) -> None:
        """Accept token invalidation requests without side effects."""
        del token, user


def _make_backend() -> AuthenticationBackend[_RouterTestUser, object]:
    """Return a typed backend stub for router contract tests."""
    return AuthenticationBackend(
        name="test",
        transport=_RouterTestTransport(),
        strategy=_RouterTestStrategy(),
    )


def _make_user_manager() -> OAuthControllerUserManagerProtocol[_RouterTestUser, object]:
    """Return a typed user-manager stub for router contract tests."""
    return cast("OAuthControllerUserManagerProtocol[_RouterTestUser, object]", object())


def test_oauth_router_module_executes_under_coverage() -> None:
    """Reload the module in-test so coverage records its module-level definitions."""
    reloaded_module = importlib.reload(router_module)

    assert reloaded_module is router_module
    assert reloaded_module.create_provider_oauth_controller.__name__ == create_provider_oauth_controller.__name__
    assert reloaded_module.load_httpx_oauth_client.__name__ == load_httpx_oauth_client.__name__


def test_create_provider_oauth_controller_missing_client_config_raises_configuration_error() -> None:
    """Factory without any client configuration raises `ConfigurationError`."""
    backend = _make_backend()
    user_manager = _make_user_manager()

    with pytest.raises(router_module.ConfigurationError, match="Provide oauth_client"):
        router_module.create_provider_oauth_controller(
            provider_name="example",
            backend=backend,
            user_manager=user_manager,
            oauth_client=None,
            oauth_client_factory=None,
            oauth_client_class=None,
            redirect_base_url="https://example.test",
        )


def test_load_httpx_oauth_client_invalid_class_path_raises_configuration_error() -> None:
    """Unresolvable client class path raises `ConfigurationError`."""
    invalid_path = "litestar_auth.oauth.router.NonExistentClient"

    with pytest.raises(router_module.ConfigurationError, match=r"could not be imported"):
        router_module.load_httpx_oauth_client(invalid_path)


def test_load_httpx_oauth_client_httpx_oauth_missing_raises_import_error_with_hint(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Missing `httpx-oauth` dependency surfaces as `ImportError` with install hint."""
    oauth_path = "httpx_oauth.clients.github.GitHubOAuth2"

    exc = ModuleNotFoundError(f"No module named {oauth_path!r}")
    exc.name = "httpx_oauth"
    monkeypatch.setattr(router, "import_module", lambda *_: (_ for _ in ()).throw(exc))

    with pytest.raises(ImportError, match=r"Install litestar-auth\[oauth]"):
        router_module.load_httpx_oauth_client(oauth_path)


def test_load_httpx_oauth_client_instantiates_client_from_imported_module(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A valid fully qualified class path should return an instantiated OAuth client."""

    class FakeClient:
        """Minimal OAuth client stub for import-based construction."""

        def __init__(self, *, client_id: str, client_secret: str) -> None:
            """Store constructor kwargs for later assertions."""
            self.client_id = client_id
            self.client_secret = client_secret

    module_name = "tests.unit.fake_oauth_router_client"
    fake_module = types.ModuleType(module_name)
    fake_module.__dict__["FakeClient"] = FakeClient
    monkeypatch.setitem(sys.modules, module_name, fake_module)

    client = router_module.load_httpx_oauth_client(
        f"{module_name}.FakeClient",
        client_id="client-id",
        client_secret="client-secret",
    )

    assert isinstance(client, FakeClient)
    assert client.client_id == "client-id"
    assert client.client_secret == "client-secret"


def test_create_provider_oauth_controller_uses_factory_client(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A factory-provided OAuth client should be passed through to the controller factory."""
    backend = _make_backend()
    user_manager = _make_user_manager()
    oauth_client = object()
    controller = cast("type[Any]", object())
    create_controller = Mock(return_value=controller)
    monkeypatch.setattr(router_module, "create_oauth_controller", create_controller)

    created_controller = router_module.create_provider_oauth_controller(
        provider_name="example",
        backend=backend,
        user_manager=user_manager,
        oauth_client_factory=lambda: oauth_client,
        redirect_base_url="https://example.test",
    )

    assert created_controller is controller
    create_controller.assert_called_once_with(
        provider_name="example",
        backend=backend,
        user_manager=user_manager,
        oauth_client=oauth_client,
        redirect_base_url="https://example.test",
        path="/auth/oauth",
        cookie_secure=True,
        associate_by_email=False,
        trust_provider_email_verified=False,
    )


def test_create_provider_oauth_controller_derives_path_from_auth_path(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Canonical helper derives the login route prefix from ``auth_path`` when ``path`` is omitted."""
    backend = _make_backend()
    user_manager = _make_user_manager()
    oauth_client = object()
    controller = cast("type[Any]", object())
    create_controller = Mock(return_value=controller)
    monkeypatch.setattr(router_module, "create_oauth_controller", create_controller)

    created_controller = router_module.create_provider_oauth_controller(
        provider_name="example",
        backend=backend,
        user_manager=user_manager,
        oauth_client=oauth_client,
        redirect_base_url="https://example.test/identity/oauth",
        auth_path="/identity",
    )

    assert created_controller is controller
    create_controller.assert_called_once_with(
        provider_name="example",
        backend=backend,
        user_manager=user_manager,
        oauth_client=oauth_client,
        redirect_base_url="https://example.test/identity/oauth",
        path="/identity/oauth",
        cookie_secure=True,
        associate_by_email=False,
        trust_provider_email_verified=False,
    )


def test_create_provider_oauth_controller_loads_client_from_class_path(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A client class path should be resolved lazily and forwarded to the controller factory."""
    backend = _make_backend()
    user_manager = _make_user_manager()
    oauth_client = object()
    controller = cast("type[Any]", object())
    create_controller = Mock(return_value=controller)
    load_client = Mock(return_value=oauth_client)
    monkeypatch.setattr(router_module, "create_oauth_controller", create_controller)
    monkeypatch.setattr(router_module, "load_httpx_oauth_client", load_client)

    created_controller = router_module.create_provider_oauth_controller(
        provider_name="example",
        backend=backend,
        user_manager=user_manager,
        oauth_client_class="tests.fake.Client",
        oauth_client_kwargs={"client_id": "client-id"},
        redirect_base_url="https://example.test",
    )

    assert created_controller is controller
    load_client.assert_called_once_with("tests.fake.Client", client_id="client-id")
    create_controller.assert_called_once_with(
        provider_name="example",
        backend=backend,
        user_manager=user_manager,
        oauth_client=oauth_client,
        redirect_base_url="https://example.test",
        path="/auth/oauth",
        cookie_secure=True,
        associate_by_email=False,
        trust_provider_email_verified=False,
    )


def test_load_httpx_oauth_client_requires_fully_qualified_path() -> None:
    """A missing module path should raise `ConfigurationError`."""
    with pytest.raises(router_module.ConfigurationError, match="fully qualified module path"):
        router_module.load_httpx_oauth_client("FakeClient")


def test_load_httpx_oauth_client_re_raises_non_httpx_module_not_found(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Non-`httpx_oauth` import failures should propagate unchanged."""
    exc = ModuleNotFoundError("No module named 'missing_dependency'")
    exc.name = "missing_dependency"
    monkeypatch.setattr(router, "import_module", lambda *_: (_ for _ in ()).throw(exc))

    with pytest.raises(ModuleNotFoundError, match="missing_dependency"):
        router_module.load_httpx_oauth_client("missing.module.Client")
