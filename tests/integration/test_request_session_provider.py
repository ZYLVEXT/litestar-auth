"""Integration coverage for the borrowed request-session seam."""

from __future__ import annotations

import asyncio
from typing import TYPE_CHECKING, Any, cast
from uuid import UUID

import pytest
from litestar import Litestar, get
from litestar.di import NamedDependency, Provide
from litestar.testing import AsyncTestClient

from litestar_auth.authentication.backend import AuthenticationBackend
from litestar_auth.authentication.transport.cookie import CookieTransport
from litestar_auth.manager import UserManagerSecurity
from litestar_auth.plugin import LitestarAuth, LitestarAuthConfig
from tests.integration.test_orchestrator import (
    ExampleUser,
    InMemoryUserDatabase,
    PluginUserManager,
    build_test_redis_strategy,
)

if TYPE_CHECKING:
    from litestar.connection import ASGIConnection
    from litestar.datastructures.state import State
    from litestar.middleware.authentication import AuthenticationResult
    from litestar.types import Scope
    from sqlalchemy.ext.asyncio import AsyncSession

pytestmark = pytest.mark.integration
HTTP_OK = 200
_DbSession = NamedDependency[object]


async def test_request_session_provider_resolves_once_for_middleware_hook_and_handler() -> None:
    """Real Litestar wiring shares one borrowed session while keeping DI caching disabled."""
    session = object()
    provider_calls = 0
    hook_sessions: list[object] = []

    async def request_session_provider(_state: State, _scope: Scope) -> AsyncSession:
        nonlocal provider_calls
        provider_calls += 1
        await asyncio.sleep(0)
        return cast("AsyncSession", session)

    async def authentication_result_hook(
        _connection: ASGIConnection[Any, Any, Any, Any],
        bound_session: AsyncSession,
        result: AuthenticationResult,
    ) -> None:
        await asyncio.sleep(0)
        assert result.user is None
        assert result.auth is None
        hook_sessions.append(bound_session)

    @get("/session-identity", sync_to_thread=False)
    def session_identity(db_session: _DbSession) -> dict[str, bool | int]:
        return {
            "provider_calls": provider_calls,
            "hook_matches_handler": hook_sessions == [db_session],
            "handler_matches_source": db_session is session,
        }

    config = LitestarAuthConfig[ExampleUser, UUID](
        backends=[
            AuthenticationBackend[ExampleUser, UUID](
                name="primary",
                transport=CookieTransport(allow_insecure_cookie_auth=True),
                strategy=build_test_redis_strategy(key_prefix="request-session-provider"),
            ),
        ],
        user_model=ExampleUser,
        user_manager_class=PluginUserManager,
        user_db_factory=lambda _session: InMemoryUserDatabase([]),
        user_manager_security=UserManagerSecurity[UUID](
            verification_token_secret="0123456789abcdef" * 4,
            reset_password_token_secret="fedcba9876543210" * 4,
            id_parser=UUID,
        ),
        request_session_provider=request_session_provider,
        authentication_result_hook=authentication_result_hook,
        include_register=False,
        include_verify=False,
        include_reset_password=False,
    )
    app = Litestar(route_handlers=[session_identity], plugins=[LitestarAuth(config)])
    registered = app.dependencies[config.db_session_dependency_key]
    assert isinstance(registered, Provide)
    assert registered.use_cache is False

    async with AsyncTestClient(app=app) as client:
        response = await client.get("/session-identity")

    assert response.status_code == HTTP_OK
    assert response.json() == {
        "provider_calls": 1,
        "hook_matches_handler": True,
        "handler_matches_source": True,
    }
