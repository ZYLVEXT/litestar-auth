"""Integration tests for plugin-owned session/device management routes."""

from __future__ import annotations

import hashlib
import hmac
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from typing import TYPE_CHECKING, Any, cast
from uuid import UUID

import pytest
from litestar import Litestar
from litestar.openapi.config import OpenAPIConfig
from litestar.testing import AsyncTestClient
from sqlalchemy import MetaData, select

from litestar_auth._plugin.config import DatabaseTokenAuthConfig
from litestar_auth._plugin.controllers import (
    create_session_devices_controller as create_plugin_session_devices_controller,
)
from litestar_auth.authentication.backend import AuthenticationBackend
from litestar_auth.authentication.strategy.base import RefreshSession, Strategy, UserManagerProtocol
from litestar_auth.authentication.transport.bearer import BearerTransport
from litestar_auth.controllers import create_session_devices_controller
from litestar_auth.exceptions import ErrorCode
from litestar_auth.manager import BaseUserManager, UserManagerSecurity
from litestar_auth.models import User, import_token_orm_models
from litestar_auth.password import PasswordHelper
from litestar_auth.plugin import LitestarAuth, LitestarAuthConfig
from tests.e2e.conftest import SessionMaker, assert_structural_session_factory
from tests.integration.conftest import InMemoryUserDatabase
from tests.integration.test_orchestrator import DummySessionMaker, ExampleUser, InMemoryTokenStrategy, PluginUserManager

if TYPE_CHECKING:
    from sqlalchemy.orm import Session

pytestmark = pytest.mark.integration

HTTP_OK = 200
HTTP_CREATED = 201
HTTP_NO_CONTENT = 204
HTTP_BAD_REQUEST = 400
HTTP_UNAUTHORIZED = 401
HTTP_NOT_FOUND = 404
_TOKEN_HASH_SECRET = "test-token-hash-secret-1234567890-1234567890"

AccessToken, RefreshToken = import_token_orm_models()


@dataclass(slots=True)
class _RequestStub:
    """Minimal request object carrying an authenticated user."""

    user: ExampleUser


class _SessionManagementStrategy(Strategy[ExampleUser, UUID]):
    """Test strategy implementing the refresh-session management protocol."""

    async def read_token(
        self,
        token: str | None,
        user_manager: UserManagerProtocol[ExampleUser, UUID],
    ) -> ExampleUser | None:
        """Return no user; route tests call management methods directly."""
        del token, user_manager
        return None

    async def write_token(self, user: ExampleUser) -> str:
        """Return a placeholder access token.

        Returns:
            Placeholder token.
        """
        del user
        return "access-token"

    async def destroy_token(self, token: str, user: ExampleUser) -> None:
        """Ignore access-token destruction for the management-only test strategy."""
        del token, user

    async def list_refresh_sessions(self, user: ExampleUser) -> list[RefreshSession]:
        """Return one public refresh session for ``user``.

        Returns:
            Public refresh-session metadata.
        """
        return [
            RefreshSession(
                session_id=f"session-{user.id}",
                created_at=datetime(2026, 5, 9, tzinfo=UTC),
                last_used_at=None,
                client_metadata=None,
            ),
        ]

    async def revoke_refresh_session(self, user: ExampleUser, session_id: str) -> bool:
        """Return whether ``session_id`` belongs to ``user``.

        Returns:
            ``True`` for the strategy-owned session id.
        """
        return session_id == f"session-{user.id}"

    async def revoke_other_refresh_sessions(self, user: ExampleUser, current_session_id: str | None) -> int:
        """Record no state and report one revoked session.

        Returns:
            Number of revoked sessions.
        """
        del user, current_session_id
        return 1


class _UnsafeMetadataSessionManagementStrategy(_SessionManagementStrategy):
    """Test strategy returning metadata that must be sanitized by the public controller."""

    async def list_refresh_sessions(self, user: ExampleUser) -> list[RefreshSession]:
        """Return one refresh session with mixed safe and unsafe metadata."""
        return [
            RefreshSession(
                session_id=f"session-{user.id}",
                created_at=datetime(2026, 5, 9, tzinfo=UTC),
                last_used_at=None,
                client_metadata=cast(
                    "Any",
                    {
                        "user_agent": "  LitestarAuth\nTest/1.0  ",
                        "oversized": "x" * 300,
                        "empty": " \n\t ",
                        "bad-key!": "invalid",
                        "x" * 65: "invalid",
                        1: "invalid",
                        "nested": {"invalid": "value"},
                    },
                ),
            ),
        ]


@pytest.fixture
def sqlalchemy_metadata() -> tuple[MetaData, ...]:
    """Create user and bundled token tables for session/device route tests.

    Returns:
        Metadata collections required by this module.
    """
    return tuple(dict.fromkeys((User.metadata, AccessToken.metadata, RefreshToken.metadata)))


def _create_user(session: Session, email: str) -> User:
    """Persist a verified user with a known password.

    Returns:
        Stored user.
    """
    user = User(
        email=email,
        hashed_password=PasswordHelper().hash("correct-password"),
        is_verified=True,
    )
    session.add(user)
    session.commit()
    session.refresh(user)
    return user


def _build_database_token_app(session: Session) -> Litestar:
    """Create a plugin app with DB-backed refresh-session routes enabled.

    Returns:
        Litestar app configured for DB-token session/device routes.
    """
    return Litestar(
        plugins=[
            LitestarAuth(
                LitestarAuthConfig[User, UUID](
                    user_model=User,
                    user_manager_class=BaseUserManager,
                    database_token_auth=DatabaseTokenAuthConfig(
                        token_hash_secret=_TOKEN_HASH_SECRET,
                        refresh_max_age=timedelta(days=30),
                    ),
                    session_maker=cast(
                        "Any",
                        assert_structural_session_factory(SessionMaker(cast("Any", session.get_bind()))),
                    ),
                    user_manager_security=UserManagerSecurity[UUID](
                        verification_token_secret="0123456789abcdef" * 4,
                        reset_password_token_secret="fedcba9876543210" * 4,
                    ),
                    include_register=False,
                    include_verify=False,
                    include_reset_password=False,
                    include_users=False,
                    include_session_devices=True,
                    enable_refresh=True,
                    requires_verification=False,
                ),
            ),
        ],
        openapi_config=OpenAPIConfig(title="Test", version="1.0.0"),
    )


async def _login(client: AsyncTestClient[Litestar], email: str) -> dict[str, str]:
    """Authenticate and return the token response payload.

    Returns:
        Token response payload.
    """
    response = await client.post(
        "/auth/login",
        json={"identifier": email, "password": "correct-password"},
        headers={"User-Agent": "LitestarAuth Session Test/1.0"},
    )
    assert response.status_code == HTTP_CREATED
    return cast("dict[str, str]", response.json())


def _refresh_digest(refresh_token: str) -> str:
    """Return the stored digest for a raw refresh token."""
    return hmac.new(_TOKEN_HASH_SECRET.encode(), refresh_token.encode(), hashlib.sha256).hexdigest()


def _auth_headers(access_token: str) -> dict[str, str]:
    """Return bearer auth headers for ``access_token``."""
    return {"Authorization": f"Bearer {access_token}"}


async def test_plugin_mounts_session_device_routes_when_feature_flag_is_enabled(session: Session) -> None:
    """The opt-in plugin flag mounts authenticated session/device routes."""
    _create_user(session, "user@example.com")
    app = _build_database_token_app(session)

    async with AsyncTestClient(app=app) as client:
        tokens = await _login(client, "user@example.com")
        response = await client.get("/auth/sessions", headers=_auth_headers(tokens["access_token"]))

    assert response.status_code == HTTP_OK
    assert response.json()["sessions"][0]["client_metadata"] == {
        "user_agent": "LitestarAuth Session Test/1.0",
    }


async def test_session_device_routes_list_and_revoke_only_current_user_sessions(session: Session) -> None:
    """List, revoke-one, and foreign-session handling are scoped to ``request.user``."""
    _create_user(session, "owner@example.com")
    _create_user(session, "other@example.com")
    app = _build_database_token_app(session)

    async with AsyncTestClient(app=app) as client:
        owner_tokens = await _login(client, "owner@example.com")
        other_tokens = await _login(client, "other@example.com")

        owner_list = await client.get("/auth/sessions", headers=_auth_headers(owner_tokens["access_token"]))
        other_list = await client.get("/auth/sessions", headers=_auth_headers(other_tokens["access_token"]))
        owner_session_id = owner_list.json()["sessions"][0]["session_id"]
        other_session_id = other_list.json()["sessions"][0]["session_id"]

        foreign_revoke = await client.delete(
            f"/auth/sessions/{other_session_id}",
            headers=_auth_headers(owner_tokens["access_token"]),
        )
        revoke = await client.delete(
            f"/auth/sessions/{owner_session_id}",
            headers=_auth_headers(owner_tokens["access_token"]),
        )
        owner_after_revoke = await client.get("/auth/sessions", headers=_auth_headers(owner_tokens["access_token"]))
        other_after_revoke = await client.get("/auth/sessions", headers=_auth_headers(other_tokens["access_token"]))

    assert owner_list.status_code == HTTP_OK
    assert [session_item["session_id"] for session_item in owner_list.json()["sessions"]] == [owner_session_id]
    assert [session_item["session_id"] for session_item in other_list.json()["sessions"]] == [other_session_id]
    assert owner_list.json()["sessions"][0]["is_current"] is None
    assert foreign_revoke.status_code == HTTP_NOT_FOUND
    assert foreign_revoke.json() == {
        "detail": "Refresh session not found.",
        "code": ErrorCode.REFRESH_SESSION_NOT_FOUND.value,
    }
    assert revoke.status_code == HTTP_NO_CONTENT
    assert owner_after_revoke.json() == {"sessions": []}
    assert [session_item["session_id"] for session_item in other_after_revoke.json()["sessions"]] == [other_session_id]


async def test_session_device_routes_mark_current_session_from_bearer_refresh_body(session: Session) -> None:
    """Bearer clients can submit the existing refresh-token body to mark the current session."""
    user = _create_user(session, "user@example.com")
    app = _build_database_token_app(session)

    async with AsyncTestClient(app=app) as client:
        current_tokens = await _login(client, "user@example.com")
        other_tokens = await _login(client, "user@example.com")

        current_row = session.scalar(
            select(RefreshToken).where(RefreshToken.token == _refresh_digest(current_tokens["refresh_token"])),
        )
        other_row = session.scalar(
            select(RefreshToken).where(RefreshToken.token == _refresh_digest(other_tokens["refresh_token"])),
        )
        assert current_row is not None
        assert other_row is not None

        response = await client.post(
            "/auth/sessions",
            headers=_auth_headers(current_tokens["access_token"]),
            json={"refresh_token": current_tokens["refresh_token"]},
        )

    assert response.status_code == HTTP_OK
    sessions_by_id = {item["session_id"]: item for item in response.json()["sessions"]}
    assert sessions_by_id[current_row.session_id]["is_current"] is True
    assert sessions_by_id[other_row.session_id]["is_current"] is False
    assert {
        token.session_id for token in session.scalars(select(RefreshToken).where(RefreshToken.user_id == user.id))
    } == {
        current_row.session_id,
        other_row.session_id,
    }


async def test_session_device_routes_revoke_other_sessions_preserves_bearer_body_session(session: Session) -> None:
    """Revoke-others preserves the current session when a bearer client supplies its refresh token."""
    user = _create_user(session, "user@example.com")
    app = _build_database_token_app(session)

    async with AsyncTestClient(app=app) as client:
        current_tokens = await _login(client, "user@example.com")
        other_tokens = await _login(client, "user@example.com")
        current_row = session.scalar(
            select(RefreshToken).where(RefreshToken.token == _refresh_digest(current_tokens["refresh_token"])),
        )
        other_row = session.scalar(
            select(RefreshToken).where(RefreshToken.token == _refresh_digest(other_tokens["refresh_token"])),
        )
        assert current_row is not None
        assert other_row is not None

        response = await client.post(
            "/auth/sessions/revoke-others",
            headers=_auth_headers(current_tokens["access_token"]),
            json={"refresh_token": current_tokens["refresh_token"]},
        )
        after_revoke = await client.get("/auth/sessions", headers=_auth_headers(current_tokens["access_token"]))

    assert response.status_code == HTTP_NO_CONTENT
    assert [item["session_id"] for item in after_revoke.json()["sessions"]] == [current_row.session_id]
    assert after_revoke.json()["sessions"][0]["is_current"] is None
    assert session.scalar(select(RefreshToken).where(RefreshToken.session_id == current_row.session_id)) is not None
    assert session.scalar(select(RefreshToken).where(RefreshToken.session_id == other_row.session_id)) is None
    assert [
        token.session_id for token in session.scalars(select(RefreshToken).where(RefreshToken.user_id == user.id))
    ] == [
        current_row.session_id,
    ]


async def test_session_device_routes_treat_unresolvable_bearer_refresh_body_as_unknown(session: Session) -> None:
    """Invalid, foreign, or expired refresh-token bodies do not mark a current session."""
    user = _create_user(session, "user@example.com")
    _create_user(session, "other@example.com")
    app = _build_database_token_app(session)

    async with AsyncTestClient(app=app) as client:
        user_tokens = await _login(client, "user@example.com")
        expired_tokens = await _login(client, "user@example.com")
        foreign_tokens = await _login(client, "other@example.com")

        expired_row = session.scalar(
            select(RefreshToken).where(RefreshToken.token == _refresh_digest(expired_tokens["refresh_token"])),
        )
        assert expired_row is not None
        expired_session_id = expired_row.session_id
        expired_row.created_at = datetime.now(tz=UTC) - timedelta(days=31)
        session.commit()

        expired_response = await client.post(
            "/auth/sessions",
            headers=_auth_headers(user_tokens["access_token"]),
            json={"refresh_token": expired_tokens["refresh_token"]},
        )
        foreign_response = await client.post(
            "/auth/sessions",
            headers=_auth_headers(user_tokens["access_token"]),
            json={"refresh_token": foreign_tokens["refresh_token"]},
        )

    assert expired_response.status_code == HTTP_OK
    assert {item["is_current"] for item in expired_response.json()["sessions"]} == {None}
    assert foreign_response.status_code == HTTP_OK
    assert {item["is_current"] for item in foreign_response.json()["sessions"]} == {None}
    assert session.scalar(select(RefreshToken).where(RefreshToken.session_id == expired_session_id)) is None
    assert [token.session_id for token in session.scalars(select(RefreshToken).where(RefreshToken.user_id == user.id))]


async def test_session_device_routes_revoke_other_sessions_with_unknown_current_session(session: Session) -> None:
    """The first slice revokes all current-user sessions when no current refresh session can be identified."""
    user = _create_user(session, "user@example.com")
    app = _build_database_token_app(session)

    async with AsyncTestClient(app=app) as client:
        first_tokens = await _login(client, "user@example.com")
        await _login(client, "user@example.com")

        response = await client.post(
            "/auth/sessions/revoke-others",
            headers=_auth_headers(first_tokens["access_token"]),
        )
        after_revoke = await client.get("/auth/sessions", headers=_auth_headers(first_tokens["access_token"]))

    remaining_refresh_tokens = session.scalars(select(RefreshToken).where(RefreshToken.user_id == user.id)).all()
    assert response.status_code == HTTP_NO_CONTENT
    assert after_revoke.json() == {"sessions": []}
    assert remaining_refresh_tokens == []


async def test_session_device_routes_reject_unauthenticated_requests(session: Session) -> None:
    """Session/device routes require authentication."""
    _create_user(session, "user@example.com")
    app = _build_database_token_app(session)

    async with AsyncTestClient(app=app) as client:
        response = await client.get("/auth/sessions")

    assert response.status_code == HTTP_UNAUTHORIZED


async def test_session_device_routes_return_structured_error_for_unsupported_strategy() -> None:
    """Strategies without the refresh-session management protocol fail explicitly."""
    password_helper = PasswordHelper()
    user = ExampleUser(
        id=UUID("12345678-1234-5678-1234-567812345678"),
        email="user@example.com",
        hashed_password=password_helper.hash("correct-password"),
        is_verified=True,
    )
    user_db = InMemoryUserDatabase([user])
    backend = AuthenticationBackend[ExampleUser, UUID](
        name="memory",
        transport=BearerTransport(),
        strategy=cast("Any", InMemoryTokenStrategy(token_prefix="unsupported-session-devices")),
    )
    app = Litestar(
        plugins=[
            LitestarAuth(
                LitestarAuthConfig[ExampleUser, UUID](
                    user_model=ExampleUser,
                    user_manager_class=PluginUserManager,
                    backends=[backend],
                    session_maker=cast("Any", assert_structural_session_factory(DummySessionMaker())),
                    user_db_factory=lambda _session: user_db,
                    user_manager_security=UserManagerSecurity[UUID](
                        verification_token_secret="0123456789abcdef" * 4,
                        reset_password_token_secret="fedcba9876543210" * 4,
                        id_parser=UUID,
                        password_helper=password_helper,
                    ),
                    include_register=False,
                    include_verify=False,
                    include_reset_password=False,
                    include_session_devices=True,
                    requires_verification=False,
                ),
            ),
        ],
    )

    async with AsyncTestClient(app=app) as client:
        tokens = await _login(client, "user@example.com")
        response = await client.get("/auth/sessions", headers=_auth_headers(tokens["access_token"]))

    assert response.status_code == HTTP_BAD_REQUEST
    assert response.json() == {
        "detail": "The configured auth strategy does not support refresh-session management.",
        "code": ErrorCode.SESSION_MANAGEMENT_UNSUPPORTED.value,
    }


def test_session_device_routes_publish_openapi_security_and_error_responses(session: Session) -> None:
    """Generated OpenAPI marks session/device routes protected and documents structured failures."""
    app = _build_database_token_app(session)
    paths = cast("Any", app.openapi_schema.paths)

    list_operation = paths["/auth/sessions"].get
    revoke_operation = paths["/auth/sessions/{session_id}"].delete
    revoke_others_operation = paths["/auth/sessions/revoke-others"].post

    assert list_operation.security == [{"database": []}]
    assert revoke_operation.security == [{"database": []}]
    assert revoke_others_operation.security == [{"database": []}]
    assert "400" in list_operation.responses
    assert "404" in revoke_operation.responses


async def test_manual_session_devices_controller_uses_static_backend_context() -> None:
    """The public controller factory supports manually mounted backend-bound routes."""
    user = ExampleUser(id=UUID("12345678-1234-5678-1234-567812345678"))
    backend = AuthenticationBackend[ExampleUser, UUID](
        name="manual",
        transport=BearerTransport(),
        strategy=cast("Any", _SessionManagementStrategy()),
    )
    controller_cls = create_session_devices_controller(backend=backend, path="/auth")
    controller = cast("Any", controller_cls.__new__(controller_cls))

    response = await controller_cls.__dict__["list_refresh_sessions"].fn(
        controller,
        cast("Any", _RequestStub(user)),
        None,
    )

    assert response.sessions[0].session_id == f"session-{user.id}"


async def test_manual_session_devices_controller_sanitizes_strategy_client_metadata() -> None:
    """The public controller bounds and filters metadata returned by custom strategies."""
    user = ExampleUser(id=UUID("12345678-1234-5678-1234-567812345678"))
    backend = AuthenticationBackend[ExampleUser, UUID](
        name="manual",
        transport=BearerTransport(),
        strategy=cast("Any", _UnsafeMetadataSessionManagementStrategy()),
    )
    controller_cls = create_session_devices_controller(backend=backend, path="/auth")
    controller = cast("Any", controller_cls.__new__(controller_cls))

    response = await controller_cls.__dict__["list_refresh_sessions"].fn(
        controller,
        cast("Any", _RequestStub(user)),
        None,
    )

    assert response.sessions[0].client_metadata == {
        "user_agent": "LitestarAuth Test/1.0",
        "oversized": "x" * 255,
    }


def test_manual_session_devices_controller_rejects_mixed_config_and_options() -> None:
    """The public controller factory rejects ambiguous config construction."""
    backend = AuthenticationBackend[ExampleUser, UUID](
        name="manual",
        transport=BearerTransport(),
        strategy=cast("Any", _SessionManagementStrategy()),
    )

    with pytest.raises(TypeError, match="Pass either SessionDevicesControllerConfig"):
        create_session_devices_controller(
            config=cast("Any", object()),
            backend=backend,
            path="/auth",
            security=None,
        )


async def test_plugin_session_devices_controller_falls_back_to_startup_backend_without_di() -> None:
    """The plugin controller keeps a startup-backend fallback for direct/manual invocation."""
    user = ExampleUser(id=UUID("12345678-1234-5678-1234-567812345678"))
    user_db = InMemoryUserDatabase([user])
    backend = AuthenticationBackend[ExampleUser, UUID](
        name="memory",
        transport=BearerTransport(),
        strategy=cast("Any", _SessionManagementStrategy()),
    )
    config = LitestarAuthConfig[ExampleUser, UUID](
        user_model=ExampleUser,
        user_manager_class=PluginUserManager,
        backends=[backend],
        session_maker=cast("Any", assert_structural_session_factory(DummySessionMaker())),
        user_db_factory=lambda _session: user_db,
        user_manager_security=UserManagerSecurity[UUID](
            verification_token_secret="0123456789abcdef" * 4,
            reset_password_token_secret="fedcba9876543210" * 4,
            id_parser=UUID,
        ),
        include_session_devices=True,
    )
    controller_cls = create_plugin_session_devices_controller(config=config)
    controller = cast("Any", controller_cls.__new__(controller_cls))

    response = await controller_cls.__dict__["list_refresh_sessions"].fn(
        controller,
        cast("Any", _RequestStub(user)),
    )

    assert response.sessions[0].session_id == f"session-{user.id}"
