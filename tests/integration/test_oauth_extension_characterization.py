"""Characterization coverage for the current plugin-owned OAuth wiring."""

from __future__ import annotations

from typing import TYPE_CHECKING, Any, cast
from uuid import UUID

import pytest
from cryptography.fernet import Fernet
from litestar import Litestar
from litestar.config.app import AppConfig
from litestar.testing import AsyncTestClient

from litestar_auth._plugin import OAUTH_ASSOCIATE_USER_MANAGER_DEPENDENCY_KEY
from litestar_auth._plugin.config import OAuthConfig
from litestar_auth.authentication.backend import AuthenticationBackend
from litestar_auth.authentication.transport.bearer import BearerTransport
from litestar_auth.config import OAuthProviderConfig
from litestar_auth.exceptions import ConfigurationError
from litestar_auth.manager import UserManagerSecurity
from litestar_auth.plugin import LitestarAuth, LitestarAuthConfig
from tests._helpers import ExampleUser
from tests.e2e.conftest import assert_structural_session_factory
from tests.integration.conftest import InMemoryUserDatabase

from .test_orchestrator import DummySessionMaker, InMemoryTokenStrategy, PluginUserManager

if TYPE_CHECKING:
    from litestar.routes import HTTPRoute

pytestmark = pytest.mark.integration

HTTP_FOUND = 302
OAUTH_FLOW_COOKIE_SECRET = "oauth-flow-cookie-secret-1234567890"


class _RecordingOAuthClient:
    """Minimal OAuth client that records authorize-call PKCE inputs."""

    def __init__(self) -> None:
        self.authorization_calls: list[tuple[str, str, str | list[str] | None]] = []
        self.latest_code_challenge: str | None = None
        self.latest_code_challenge_method: str | None = None

    async def get_authorization_url(
        self,
        redirect_uri: str,
        state: str,
        *,
        scope: str | list[str] | None = None,
        code_challenge: str | None = None,
        code_challenge_method: str | None = None,
    ) -> str:
        self.authorization_calls.append((redirect_uri, state, scope))
        self.latest_code_challenge = code_challenge
        self.latest_code_challenge_method = code_challenge_method
        return f"https://provider.example/authorize?state={state}"

    async def get_access_token(
        self,
        code: str,
        redirect_uri: str,
        *,
        code_verifier: str | None = None,
    ) -> dict[str, object]:
        return {"access_token": "provider-access-token"}

    async def get_id_email(self, access_token: str) -> tuple[str, str]:
        return "provider-user", "oauth@example.com"


def _oauth_encryption_key() -> str:
    return Fernet.generate_key().decode()


def _build_config(  # noqa: PLR0913
    *,
    oauth_client: object | None = None,
    include_oauth_associate: bool = False,
    redirect_base_url: str = "https://app.example.com/auth",
    oauth_token_encryption_key: str | None = None,
    unsafe_testing: bool = False,
    users: list[ExampleUser] | None = None,
) -> tuple[LitestarAuthConfig[ExampleUser, UUID], InMemoryTokenStrategy]:
    user_db = InMemoryUserDatabase(users)
    strategy = InMemoryTokenStrategy(token_prefix="oauth-extension")
    backend = AuthenticationBackend[ExampleUser, UUID](
        name="primary",
        transport=BearerTransport(),
        strategy=cast("Any", strategy),
    )
    config = LitestarAuthConfig[ExampleUser, UUID](
        backends=[backend],
        session_maker=cast("Any", assert_structural_session_factory(DummySessionMaker())),
        user_model=ExampleUser,
        user_manager_class=PluginUserManager,
        user_db_factory=lambda _session: user_db,
        user_manager_security=UserManagerSecurity[UUID](
            verification_token_secret="0123456789abcdef" * 4,
            reset_password_token_secret="fedcba9876543210" * 4,
            id_parser=UUID,
        ),
        include_users=False,
        unsafe_testing=unsafe_testing,
    )
    config.oauth_config = OAuthConfig(
        oauth_providers=[OAuthProviderConfig(name="github", client=oauth_client or _RecordingOAuthClient())],
        include_oauth_associate=include_oauth_associate,
        oauth_redirect_base_url=redirect_base_url,
        oauth_token_encryption_key=oauth_token_encryption_key,
        oauth_flow_cookie_secret=OAUTH_FLOW_COOKIE_SECRET,
    )
    return config, strategy


def _mounted_http_routes(app: Litestar) -> dict[str, set[str]]:
    routes: dict[str, set[str]] = {}
    for route in cast("list[HTTPRoute]", app.routes):
        methods = set(getattr(route, "route_handler_map", {}))
        routes[route.path] = methods - {"OPTIONS"}
    return routes


async def test_plugin_owned_oauth_login_and_associate_routes_mount_with_current_paths() -> None:
    """Configured OAuth providers mount the current login and associate route inventory."""
    oauth_client = _RecordingOAuthClient()
    user = ExampleUser(id=UUID(int=1), email="user@example.com", is_verified=True)
    config, strategy = _build_config(
        oauth_client=oauth_client,
        include_oauth_associate=True,
        oauth_token_encryption_key=_oauth_encryption_key(),
        unsafe_testing=True,
        users=[user],
    )
    app = Litestar(plugins=[LitestarAuth(config)])

    mounted_routes = _mounted_http_routes(app)

    assert mounted_routes["/auth/oauth/github/authorize"] == {"GET"}
    assert mounted_routes["/auth/oauth/github/callback"] == {"GET"}
    assert mounted_routes["/auth/associate/github/authorize"] == {"POST"}
    assert mounted_routes["/auth/associate/github/callback"] == {"GET"}

    async with AsyncTestClient(app=app) as client:
        login_response = await client.get("/auth/oauth/github/authorize", follow_redirects=False)
        token = await strategy.write_token(user)
        associate_response = await client.post(
            "/auth/associate/github/authorize",
            headers={"Authorization": f"Bearer {token}"},
            follow_redirects=False,
        )

    assert login_response.status_code == HTTP_FOUND
    assert associate_response.status_code == HTTP_FOUND
    assert oauth_client.latest_code_challenge is not None
    assert oauth_client.latest_code_challenge_method == "S256"
    assert oauth_client.authorization_calls == [
        ("https://app.example.com/auth/oauth/github/callback", oauth_client.authorization_calls[0][1], None),
        ("https://app.example.com/auth/associate/github/callback", oauth_client.authorization_calls[1][1], None),
    ]


def test_oauth_token_encryption_required_at_startup_for_configured_providers() -> None:
    """Configured OAuth providers still fail closed without token-encryption key material."""
    config, _ = _build_config(include_oauth_associate=True)
    plugin = LitestarAuth(config)

    with pytest.raises(ConfigurationError, match=r"oauth_token_encryption_key is required"):
        plugin.on_app_init(AppConfig())


def test_secure_oauth_redirect_guard_rejects_insecure_production_origin() -> None:
    """Production startup rejects insecure plugin-owned OAuth redirect origins."""
    config, _ = _build_config(
        redirect_base_url="http://localhost/auth",
        oauth_token_encryption_key=_oauth_encryption_key(),
    )
    plugin = LitestarAuth(config)

    with pytest.raises(ConfigurationError, match="public HTTPS origin"):
        plugin.on_app_init(AppConfig(debug=False))


def test_secure_oauth_redirect_guard_honors_debug_and_unsafe_testing_escapes() -> None:
    """Debug and explicit unsafe testing keep local OAuth redirect recipes available."""
    debug_config, _ = _build_config(
        redirect_base_url="http://localhost/auth",
        oauth_token_encryption_key=_oauth_encryption_key(),
    )
    unsafe_config, _ = _build_config(
        redirect_base_url="http://localhost/auth",
        oauth_token_encryption_key=_oauth_encryption_key(),
        unsafe_testing=True,
    )

    assert LitestarAuth(debug_config).on_app_init(AppConfig(debug=True)) is not None
    assert LitestarAuth(unsafe_config).on_app_init(AppConfig(debug=False)) is not None


def test_associate_user_manager_di_registered_only_for_associate_inventory() -> None:
    """Associate-only user-manager DI remains tied to the associate route surface."""
    associate_config, _ = _build_config(
        include_oauth_associate=True,
        oauth_token_encryption_key=_oauth_encryption_key(),
        unsafe_testing=True,
    )
    login_only_config, _ = _build_config(
        oauth_token_encryption_key=_oauth_encryption_key(),
        unsafe_testing=True,
    )

    associate_app_config = LitestarAuth(associate_config).on_app_init(AppConfig())
    login_only_app_config = LitestarAuth(login_only_config).on_app_init(AppConfig())

    assert OAUTH_ASSOCIATE_USER_MANAGER_DEPENDENCY_KEY in associate_app_config.dependencies
    assert OAUTH_ASSOCIATE_USER_MANAGER_DEPENDENCY_KEY not in login_only_app_config.dependencies
