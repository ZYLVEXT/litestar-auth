"""Integration tests for AsyncSession usage per HTTP request (plugin wiring)."""

from __future__ import annotations

from typing import Any, cast
from uuid import UUID, uuid4

import pytest
from litestar import Litestar
from litestar.testing import AsyncTestClient

from litestar_auth.authentication.backend import AuthenticationBackend
from litestar_auth.authentication.transport.bearer import BearerTransport
from litestar_auth.password import PasswordHelper
from litestar_auth.plugin import LitestarAuth, LitestarAuthConfig
from tests.integration.conftest import CountingSessionMaker, ExampleUser, InMemoryUserDatabase
from tests.integration.test_orchestrator import (
    InMemoryTokenStrategy,
    PluginUserManager,
    auth_state,
    dependency_probe,
)

pytestmark = pytest.mark.integration

HTTP_CREATED = 201
HTTP_OK = 200


def _build_app_with_counting_session_maker() -> tuple[Litestar, CountingSessionMaker]:
    """LitestarAuth app with :class:`CountingSessionMaker` (same shape as orchestrator tests).

    Returns:
        Application instance and the counting session factory for assertions.
    """
    password_helper = PasswordHelper()
    regular_user = ExampleUser(
        id=uuid4(),
        email="user@example.com",
        hashed_password=password_helper.hash("user-password"),
        is_verified=True,
    )
    user_db = InMemoryUserDatabase([regular_user])
    primary_strategy = InMemoryTokenStrategy(token_prefix="primary")
    secondary_strategy = InMemoryTokenStrategy(token_prefix="secondary")
    backends = [
        AuthenticationBackend[ExampleUser, UUID](
            name="primary",
            transport=BearerTransport(),
            strategy=cast("Any", primary_strategy),
        ),
        AuthenticationBackend[ExampleUser, UUID](
            name="secondary",
            transport=BearerTransport(),
            strategy=cast("Any", secondary_strategy),
        ),
    ]
    counting = CountingSessionMaker()
    config = LitestarAuthConfig[ExampleUser, UUID](
        backends=backends,
        session_maker=cast("Any", counting),
        user_model=ExampleUser,
        user_manager_class=PluginUserManager,
        user_db_factory=lambda _session: user_db,
        user_manager_kwargs={
            "password_helper": password_helper,
            "verification_token_secret": "verify-secret-12345678901234567890",
            "reset_password_token_secret": "reset-secret-123456789012345678901",
            "id_parser": UUID,
        },
        include_users=True,
    )
    plugin = LitestarAuth(config)
    app = Litestar(route_handlers=[dependency_probe, auth_state], plugins=[plugin])
    return app, counting


@pytest.mark.asyncio
async def test_single_session_per_request() -> None:
    """Exactly one ``session_maker()`` call per request (login + users controller)."""
    app, counting = _build_app_with_counting_session_maker()
    async with AsyncTestClient(app=app) as client:
        before_login = counting.call_count
        login_response = await client.post(
            "/auth/login",
            json={"identifier": "user@example.com", "password": "user-password"},
        )
        login_sessions = counting.call_count - before_login

        assert login_response.status_code == HTTP_CREATED
        token = login_response.json()["access_token"]

        before_me = counting.call_count
        me_response = await client.get(
            "/users/me",
            headers={"Authorization": f"Bearer {token}"},
        )
        me_sessions = counting.call_count - before_me

    assert me_response.status_code == HTTP_OK
    assert login_sessions == 1
    assert me_sessions == 1
