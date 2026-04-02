"""OpenAPI regression tests for controller request-body contracts."""

from __future__ import annotations

from typing import Any, cast
from uuid import UUID

import pytest
from litestar import Litestar

from litestar_auth.authentication.backend import AuthenticationBackend
from litestar_auth.authentication.transport.bearer import BearerTransport
from litestar_auth.password import PasswordHelper
from litestar_auth.plugin import LitestarAuth, LitestarAuthConfig
from tests._helpers import ExampleUser
from tests.integration.conftest import DummySessionMaker, InMemoryUserDatabase
from tests.integration.test_controller_totp import build_app as build_totp_app
from tests.integration.test_controller_users import build_app as build_users_app
from tests.integration.test_orchestrator import InMemoryRefreshTokenStrategy, PluginUserManager

pytestmark = pytest.mark.integration


def _build_plugin_openapi_app() -> Litestar:
    """Build a plugin-mounted app using the consumer-reported ``/auth/jwt`` prefix.

    Returns:
        Litestar app exposing plugin-managed auth routes under ``/auth/jwt``.
    """
    config = LitestarAuthConfig[ExampleUser, UUID](
        backends=[
            AuthenticationBackend[ExampleUser, UUID](
                name="primary",
                transport=BearerTransport(),
                strategy=cast("Any", InMemoryRefreshTokenStrategy(token_prefix="openapi")),
            ),
        ],
        session_maker=cast("Any", DummySessionMaker()),
        user_model=ExampleUser,
        user_manager_class=PluginUserManager,
        user_db_factory=lambda _session: InMemoryUserDatabase([]),
        user_manager_kwargs={
            "password_helper": PasswordHelper(),
            "verification_token_secret": "verify-secret-12345678901234567890",
            "reset_password_token_secret": "reset-secret-123456789012345678901",
            "id_parser": UUID,
        },
        auth_path="/auth/jwt",
        enable_refresh=True,
        include_users=False,
        include_verify=False,
    )
    return Litestar(plugins=[LitestarAuth(config)])


def _request_body_ref(app: Litestar, *, path: str, method_name: str) -> str | None:
    """Return the OpenAPI request-body schema ref for an operation, if any."""
    operation = getattr(cast("Any", app.openapi_schema.paths)[path], method_name)
    request_body = operation.request_body
    if request_body is None:
        return None
    media_type = next(iter(request_body.content.values()))
    return media_type.schema.ref


@pytest.fixture
def plugin_app() -> Litestar:
    """Provide the plugin-mounted app used to lock `/auth/jwt/*` schema paths.

    Returns:
        Litestar app exposing the plugin-mounted auth schema.
    """
    return _build_plugin_openapi_app()


@pytest.mark.parametrize(
    ("path", "schema_ref"),
    [
        ("/auth/jwt/login", "#/components/schemas/LoginCredentials"),
        ("/auth/jwt/register", "#/components/schemas/UserCreate"),
        ("/auth/jwt/reset-password", "#/components/schemas/ResetPassword"),
        ("/auth/jwt/refresh", "#/components/schemas/RefreshTokenRequest"),
    ],
)
def test_plugin_mounted_auth_routes_publish_expected_request_bodies(
    plugin_app: Litestar,
    path: str,
    schema_ref: str,
) -> None:
    """Plugin-mounted auth routes retain the documented `/auth/jwt/*` request bodies."""
    paths = cast("Any", plugin_app.openapi_schema.paths)

    assert "/auth/login" not in paths
    assert path in paths
    assert _request_body_ref(plugin_app, path=path, method_name="post") == schema_ref


@pytest.mark.parametrize("path", ["/users/me", "/users/{user_id}"])
def test_direct_users_patch_routes_publish_expected_request_bodies(path: str) -> None:
    """Direct users-controller patch routes retain their request-body contract."""
    app, *_ = build_users_app()

    assert _request_body_ref(app, path=path, method_name="patch") == "#/components/schemas/UserUpdate"


def test_direct_totp_routes_publish_expected_request_bodies_when_step_up_is_enabled() -> None:
    """Direct TOTP routes retain the documented request bodies when step-up is required."""
    app, *_ = build_totp_app(totp_enable_requires_password=True)

    assert _request_body_ref(app, path="/auth/2fa/enable", method_name="post") == (
        "#/components/schemas/TotpEnableRequest"
    )
    assert _request_body_ref(app, path="/auth/2fa/verify", method_name="post") == (
        "#/components/schemas/TotpVerifyRequest"
    )


def test_direct_totp_enable_omits_request_body_when_step_up_is_disabled() -> None:
    """Password-optional direct TOTP enable keeps the no-body contract while verify stays documented."""
    app, *_ = build_totp_app(totp_enable_requires_password=False)

    assert _request_body_ref(app, path="/auth/2fa/enable", method_name="post") is None
    assert _request_body_ref(app, path="/auth/2fa/verify", method_name="post") == (
        "#/components/schemas/TotpVerifyRequest"
    )
