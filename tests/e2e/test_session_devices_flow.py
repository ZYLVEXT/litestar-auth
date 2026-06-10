"""End-to-end session/device management flow through the plugin stack."""

from __future__ import annotations

from datetime import timedelta
from typing import TYPE_CHECKING, Any, cast
from uuid import UUID

import pytest
from litestar import Litestar

from litestar_auth._plugin.config import DatabaseTokenAuthConfig
from litestar_auth.exceptions import ErrorCode
from litestar_auth.manager import BaseUserManager, UserManagerSecurity
from litestar_auth.models import User, import_token_orm_models
from litestar_auth.plugin import LitestarAuth, LitestarAuthConfig
from tests.e2e.conftest import SessionMaker, assert_structural_session_factory

if TYPE_CHECKING:
    from litestar.testing import AsyncTestClient
    from sqlalchemy.orm import Session
    from sqlalchemy.schema import MetaData

pytestmark = pytest.mark.e2e

HTTP_CREATED = 201
HTTP_OK = 200
HTTP_NO_CONTENT = 204
HTTP_BAD_REQUEST = 400
HTTP_NOT_FOUND = 404
TOKEN_HASH_SECRET = "test-token-hash-secret-1234567890-1234567890"

AccessToken, RefreshToken, RefreshTokenConsumedDigest = import_token_orm_models()


@pytest.fixture
def sqlalchemy_metadata() -> tuple[MetaData, ...]:
    """Create user and bundled token tables for DB-backed e2e session tests.

    Returns:
        Metadata collections required by this module.
    """
    return tuple(dict.fromkeys((User.metadata, AccessToken.metadata, RefreshTokenConsumedDigest.metadata)))


@pytest.fixture
def app(session: Session) -> Litestar:
    """Create a plugin app exposing register, login, refresh, and session/device routes.

    Returns:
        Litestar app wired with the database-token auth backend.
    """
    return Litestar(
        plugins=[
            LitestarAuth(
                LitestarAuthConfig[User, UUID](
                    user_model=User,
                    user_manager_class=BaseUserManager,
                    database_token_auth=DatabaseTokenAuthConfig(
                        token_hash_secret=TOKEN_HASH_SECRET,
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
                    include_verify=False,
                    include_reset_password=False,
                    include_users=True,
                    include_session_devices=True,
                    enable_refresh=True,
                    requires_verification=False,
                ),
            ),
        ],
    )


async def _register(client: AsyncTestClient[Litestar], email: str) -> None:
    response = await client.post(
        "/auth/register",
        json={"email": email, "password": "correct-password"},
    )
    assert response.status_code == HTTP_CREATED


async def _login(client: AsyncTestClient[Litestar], email: str, user_agent: str) -> dict[str, str]:
    response = await client.post(
        "/auth/login",
        json={"identifier": email, "password": "correct-password"},
        headers={"User-Agent": user_agent},
    )
    assert response.status_code == HTTP_CREATED
    return cast("dict[str, str]", response.json())


async def _refresh(client: AsyncTestClient[Litestar], refresh_token: str, user_agent: str) -> dict[str, str]:
    response = await client.post(
        "/auth/refresh",
        json={"refresh_token": refresh_token},
        headers={"User-Agent": user_agent},
    )
    assert response.status_code == HTTP_CREATED
    return cast("dict[str, str]", response.json())


def _auth_headers(access_token: str) -> dict[str, str]:
    return {"Authorization": f"Bearer {access_token}"}


async def _list_sessions(
    client: AsyncTestClient[Litestar],
    access_token: str,
    refresh_token: str,
) -> dict[str, dict[str, object]]:
    response = await client.post(
        "/auth/sessions",
        headers=_auth_headers(access_token),
        json={"refresh_token": refresh_token},
    )
    assert response.status_code == HTTP_OK
    return {cast("str", item["session_id"]): item for item in response.json()["sessions"]}


async def _assert_refresh_token_invalid(client: AsyncTestClient[Litestar], refresh_token: str) -> None:
    response = await client.post("/auth/refresh", json={"refresh_token": refresh_token})

    assert response.status_code == HTTP_BAD_REQUEST
    payload = response.json()
    code = payload.get("code") or (payload.get("extra") or {}).get("code")
    assert code == ErrorCode.REFRESH_TOKEN_INVALID


async def test_db_backed_session_devices_full_plugin_flow(client: AsyncTestClient[Litestar]) -> None:
    """Users manage only their own DB refresh sessions and revoked refresh tokens fail."""
    await _register(client, "owner@example.com")
    await _register(client, "other@example.com")

    owner_current = await _login(client, "owner@example.com", "Owner Current/1.0")
    owner_other = await _login(client, "owner@example.com", "Owner Other/1.0")
    other = await _login(client, "other@example.com", "Other Current/1.0")

    owner_sessions = await _list_sessions(
        client,
        owner_current["access_token"],
        owner_current["refresh_token"],
    )
    other_sessions = await _list_sessions(client, other["access_token"], other["refresh_token"])
    owner_current_id = next(session_id for session_id, item in owner_sessions.items() if item["is_current"] is True)
    owner_other_id = next(session_id for session_id, item in owner_sessions.items() if item["is_current"] is False)
    other_session_id = next(iter(other_sessions))

    assert set(owner_sessions) == {owner_current_id, owner_other_id}
    assert owner_sessions[owner_current_id]["client_metadata"] == {"user_agent": "Owner Current/1.0"}
    assert owner_sessions[owner_other_id]["client_metadata"] == {"user_agent": "Owner Other/1.0"}

    rotated_owner_current = await _refresh(
        client,
        owner_current["refresh_token"],
        "Owner Current Refreshed/2.0",
    )
    owner_current = rotated_owner_current

    owner_after_rotation = await _list_sessions(
        client,
        owner_current["access_token"],
        owner_current["refresh_token"],
    )
    assert set(owner_after_rotation) == {owner_current_id, owner_other_id}
    assert owner_after_rotation[owner_current_id]["is_current"] is True
    assert owner_after_rotation[owner_current_id]["client_metadata"] == {
        "user_agent": "Owner Current Refreshed/2.0",
    }

    foreign_revoke = await client.delete(
        f"/auth/sessions/{other_session_id}",
        headers=_auth_headers(owner_current["access_token"]),
    )
    assert foreign_revoke.status_code == HTTP_NOT_FOUND
    assert next(iter(await _list_sessions(client, other["access_token"], other["refresh_token"]))) == other_session_id

    revoke_owner_other = await client.delete(
        f"/auth/sessions/{owner_other_id}",
        headers=_auth_headers(owner_current["access_token"]),
    )
    assert revoke_owner_other.status_code == HTTP_NO_CONTENT
    await _assert_refresh_token_invalid(client, owner_other["refresh_token"])
    owner_current = await _refresh(client, owner_current["refresh_token"], "Owner Current Survived/3.0")

    owner_extra = await _login(client, "owner@example.com", "Owner Extra/1.0")
    owner_before_revoke_others = await _list_sessions(
        client,
        owner_current["access_token"],
        owner_current["refresh_token"],
    )
    owner_extra_id = next(
        session_id for session_id, item in owner_before_revoke_others.items() if item["is_current"] is False
    )

    revoke_others = await client.post(
        "/auth/sessions/revoke-others",
        headers=_auth_headers(owner_current["access_token"]),
        json={"refresh_token": owner_current["refresh_token"]},
    )
    assert revoke_others.status_code == HTTP_NO_CONTENT
    await _assert_refresh_token_invalid(client, owner_extra["refresh_token"])

    owner_after_revoke_others = await _list_sessions(
        client,
        owner_current["access_token"],
        owner_current["refresh_token"],
    )
    assert set(owner_after_revoke_others) == {owner_current_id}
    assert owner_after_revoke_others[owner_current_id]["is_current"] is True
    assert owner_extra_id not in owner_after_revoke_others
    assert next(iter(await _list_sessions(client, other["access_token"], other["refresh_token"]))) == other_session_id
    await _refresh(client, owner_current["refresh_token"], "Owner Current Survived Again/4.0")
    await _refresh(client, other["refresh_token"], "Other Current Unaffected/2.0")
