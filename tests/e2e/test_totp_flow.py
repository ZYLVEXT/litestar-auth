"""End-to-end TOTP flow through the Litestar auth plugin."""

from __future__ import annotations

import sqlite3
from typing import TYPE_CHECKING, Any, cast
from uuid import UUID

import pytest
from cryptography.fernet import Fernet
from litestar import Litestar, Request, get
from sqlalchemy import create_engine, event
from sqlalchemy.orm import Session as SASession
from sqlalchemy.pool import StaticPool

from litestar_auth._plugin.config import TotpConfig
from litestar_auth.authentication.backend import AuthenticationBackend
from litestar_auth.authentication.strategy.jwt import JWTStrategy
from litestar_auth.authentication.transport.bearer import BearerTransport
from litestar_auth.guards import is_authenticated
from litestar_auth.manager import BaseUserManager
from litestar_auth.models import User
from litestar_auth.password import PasswordHelper
from litestar_auth.plugin import LitestarAuth, LitestarAuthConfig
from litestar_auth.totp import InMemoryUsedTotpCodeStore, _generate_totp_code
from tests.e2e.conftest import SessionMaker

if TYPE_CHECKING:
    from collections.abc import Iterator

    from litestar.testing import AsyncTestClient

pytestmark = pytest.mark.e2e

HTTP_ACCEPTED = 202
HTTP_BAD_REQUEST = 400
HTTP_CREATED = 201
HTTP_OK = 200
TOTP_PENDING_SECRET = "test-totp-pending-secret-1234567890"


class TOTPUserManager(BaseUserManager[User, UUID]):
    """Concrete manager used by the e2e TOTP app."""


@get("/protected", guards=[is_authenticated], sync_to_thread=False)
def protected_route(request: Request[Any, Any, Any]) -> dict[str, str]:
    """Expose the authenticated user's email for end-to-end checks.

    Returns:
        The authenticated email.
    """
    user = cast("User", request.user)
    return {"email": user.email}


@pytest.fixture
def app() -> Iterator[Litestar]:
    """Create a Litestar app wired with bearer JWT auth and TOTP support.

    Yields:
        App under test.
    """
    engine = create_engine(
        "sqlite+pysqlite:///:memory:",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )

    @event.listens_for(engine, "connect")
    def _enable_sqlite_foreign_keys(dbapi_connection: sqlite3.Connection, _: object) -> None:
        if not isinstance(dbapi_connection, sqlite3.Connection):
            return

        cursor = dbapi_connection.cursor()
        try:
            cursor.execute("PRAGMA foreign_keys=ON")
        finally:
            cursor.close()

    User.metadata.create_all(engine)
    password_helper = PasswordHelper()

    with SASession(engine) as session:
        session.add(
            User(
                email="user@example.com",
                hashed_password=password_helper.hash("correct-password"),
                is_verified=True,
            ),
        )
        session.commit()

    backend = AuthenticationBackend[User, UUID](
        name="bearer",
        transport=BearerTransport(),
        strategy=cast(
            "Any",
            JWTStrategy[User, UUID](
                secret="jwt-bearer-secret-1234567890-extra",
                subject_decoder=UUID,
            ),
        ),
    )
    config = LitestarAuthConfig[User, UUID](
        backends=[backend],
        session_maker=cast("Any", SessionMaker(engine)),
        user_model=User,
        user_manager_class=TOTPUserManager,
        allow_nondurable_jwt_revocation=True,
        user_manager_kwargs={
            "password_helper": password_helper,
            "verification_token_secret": "verify-secret-1234567890-1234567890",
            "reset_password_token_secret": "reset-secret-1234567890-1234567890",
            "id_parser": UUID,
            "totp_secret_key": Fernet.generate_key().decode(),
        },
        totp_config=TotpConfig(
            totp_pending_secret=TOTP_PENDING_SECRET,
            totp_used_tokens_store=InMemoryUsedTotpCodeStore(),
        ),
        id_parser=UUID,
    )
    yield Litestar(route_handlers=[protected_route], plugins=[LitestarAuth(config)])
    engine.dispose()


@pytest.fixture
def test_client_base_url() -> str:
    """Use HTTPS so cookie and redirect behavior matches production wiring.

    Returns:
        HTTPS base URL for the shared async test client fixture.
    """
    return "https://testserver.local"


@pytest.mark.filterwarnings("ignore::litestar_auth.totp.SecurityWarning")
async def test_totp_enable_verify_disable_flow(
    client: AsyncTestClient[Litestar],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A persisted user can enable, verify, and disable TOTP through the plugin."""
    fixed_counter = 123_456
    monkeypatch.setattr("litestar_auth.totp._current_counter", lambda: fixed_counter)
    initial_login_response = await client.post(
        "/auth/login",
        json={"identifier": "user@example.com", "password": "correct-password"},
    )
    assert initial_login_response.status_code == HTTP_CREATED
    initial_access_token = initial_login_response.json()["access_token"]

    enable_response = await client.post(
        "/auth/2fa/enable",
        json={"password": "correct-password"},
        headers={"Authorization": f"Bearer {initial_access_token}"},
    )
    assert enable_response.status_code == HTTP_CREATED
    enable_payload = enable_response.json()
    assert enable_payload["secret"]
    assert enable_payload["uri"].startswith("otpauth://totp/")
    assert enable_payload["enrollment_token"]

    # TOTP not yet active — login should still succeed without 2FA
    pre_confirm_login = await client.post(
        "/auth/login",
        json={"identifier": "user@example.com", "password": "correct-password"},
    )
    assert pre_confirm_login.status_code == HTTP_CREATED

    # Confirm enrollment with a valid TOTP code
    confirm_code = _generate_totp_code(enable_payload["secret"], fixed_counter)
    confirm_response = await client.post(
        "/auth/2fa/enable/confirm",
        json={
            "enrollment_token": enable_payload["enrollment_token"],
            "code": confirm_code,
        },
        headers={"Authorization": f"Bearer {initial_access_token}"},
    )
    assert confirm_response.status_code == HTTP_CREATED
    assert confirm_response.json()["enabled"] is True

    # Now TOTP is active — login should require 2FA
    pending_login_response = await client.post(
        "/auth/login",
        json={"identifier": "user@example.com", "password": "correct-password"},
    )
    assert pending_login_response.status_code == HTTP_ACCEPTED
    pending_payload = pending_login_response.json()
    assert pending_payload["totp_required"] is True

    invalid_verify_response = await client.post(
        "/auth/2fa/verify",
        json={"pending_token": pending_payload["pending_token"], "code": "000000"},
    )
    assert invalid_verify_response.status_code == HTTP_BAD_REQUEST

    valid_code = _generate_totp_code(enable_payload["secret"], fixed_counter)
    verify_response = await client.post(
        "/auth/2fa/verify",
        json={"pending_token": pending_payload["pending_token"], "code": valid_code},
    )
    assert verify_response.status_code == HTTP_CREATED
    verified_access_token = verify_response.json()["access_token"]

    protected_response = await client.get(
        "/protected",
        headers={"Authorization": f"Bearer {verified_access_token}"},
    )
    assert protected_response.status_code == HTTP_OK
    assert protected_response.json() == {"email": "user@example.com"}

    monkeypatch.setattr("litestar_auth.totp._current_counter", lambda: fixed_counter + 1)
    disable_code = _generate_totp_code(enable_payload["secret"], fixed_counter + 1)
    disable_response = await client.post(
        "/auth/2fa/disable",
        json={"code": disable_code},
        headers={"Authorization": f"Bearer {verified_access_token}"},
    )
    assert disable_response.status_code == HTTP_CREATED

    final_login_response = await client.post(
        "/auth/login",
        json={"identifier": "user@example.com", "password": "correct-password"},
    )
    assert final_login_response.status_code == HTTP_CREATED
    assert final_login_response.json()["token_type"] == "bearer"
    assert "access_token" in final_login_response.json()
