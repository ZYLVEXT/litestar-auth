"""End-to-end coverage for TOTP mounted through the internal extension path."""

from __future__ import annotations

from typing import Any, cast
from uuid import UUID, uuid4

import pytest
from cryptography.fernet import Fernet
from litestar import Litestar
from litestar.testing import AsyncTestClient

import litestar_auth.totp as _totp_mod
from litestar_auth import _totp_primitive
from litestar_auth._plugin.config import TotpConfig
from litestar_auth.authentication.backend import AuthenticationBackend
from litestar_auth.authentication.strategy.jwt import InMemoryJWTDenylistStore
from litestar_auth.authentication.transport.bearer import BearerTransport
from litestar_auth.controllers._utils import _is_litestar_auth_route_handler
from litestar_auth.exceptions import ConfigurationError, ErrorCode
from litestar_auth.manager import UserManagerSecurity
from litestar_auth.password import PasswordHelper
from litestar_auth.plugin import LitestarAuth, LitestarAuthConfig
from tests.integration.conftest import ExampleUser, InMemoryUserDatabase
from tests.integration.test_orchestrator import DummySessionMaker, InMemoryTokenStrategy, PluginUserManager

pytestmark = pytest.mark.integration

HTTP_ACCEPTED = 202
HTTP_CREATED = 201
HTTP_FORBIDDEN = 403
HTTP_OK = 200
TOTP_PENDING_SECRET = "test-totp-extension-pending-secret-123"
TOTP_RECOVERY_CODE_LOOKUP_SECRET = "test-recovery-code-lookup-secret-123"


def _build_totp_config(
    *,
    pending_secret: str = TOTP_PENDING_SECRET,
    used_tokens_store: _totp_mod.InMemoryUsedTotpCodeStore | None = None,
) -> TotpConfig:
    """Return production-shaped TOTP config for plugin-extension tests."""
    return TotpConfig(
        totp_pending_secret=pending_secret,
        totp_pending_jti_store=InMemoryJWTDenylistStore(),
        totp_enrollment_store=_totp_mod.InMemoryTotpEnrollmentStore(),
        totp_used_tokens_store=used_tokens_store,
    )


def _build_app(
    *,
    totp_config: TotpConfig | None = None,
    captured_controllers: list[object] | None = None,
) -> tuple[Litestar, InMemoryUserDatabase[ExampleUser]]:
    """Build a plugin app whose TOTP routes come only from ``config.totp_config``.

    Returns:
        Litestar app plus the backing in-memory user store.
    """
    password_helper = PasswordHelper()
    user = ExampleUser(
        id=uuid4(),
        email="user@example.com",
        hashed_password=password_helper.hash("correct-password"),
        is_verified=True,
    )
    user_db = InMemoryUserDatabase([user])
    backend = AuthenticationBackend[ExampleUser, UUID](
        name="primary",
        transport=BearerTransport(),
        strategy=cast("Any", InMemoryTokenStrategy(token_prefix="totp-extension")),
    )
    config = LitestarAuthConfig[ExampleUser, UUID](
        backends=[backend],
        session_maker=cast("Any", DummySessionMaker()),
        user_model=ExampleUser,
        user_manager_class=PluginUserManager,
        user_db_factory=lambda _session: user_db,
        user_manager_security=UserManagerSecurity[UUID](
            verification_token_secret="0123456789abcdef" * 4,
            reset_password_token_secret="fedcba9876543210" * 4,
            totp_secret_key=Fernet.generate_key().decode(),
            totp_recovery_code_lookup_secret=TOTP_RECOVERY_CODE_LOOKUP_SECRET,
            id_parser=UUID,
            password_helper=password_helper,
        ),
        include_users=True,
        totp_config=totp_config,
    )

    if captured_controllers is not None:

        def capture_controllers(controllers: list[object]) -> list[object]:
            captured_controllers.extend(controllers)
            return controllers

        config.controller_hook = cast("Any", capture_controllers)

    return Litestar(plugins=[LitestarAuth(config)]), user_db


async def _enable_totp(
    client: AsyncTestClient[Litestar],
    *,
    access_token: str,
) -> tuple[str, tuple[str, ...]]:
    """Enable TOTP for the test user.

    Returns:
        Enrollment secret plus the generated recovery codes.
    """
    enable_response = await client.post(
        "/auth/2fa/enable",
        json={"password": "correct-password"},
        headers={"Authorization": f"Bearer {access_token}"},
    )
    assert enable_response.status_code == HTTP_CREATED
    enable_body = enable_response.json()

    confirm_response = await client.post(
        "/auth/2fa/enable/confirm",
        json={
            "enrollment_token": enable_body["enrollment_token"],
            "code": _totp_primitive._generate_totp_code(enable_body["secret"], _totp_primitive._current_counter()),
        },
        headers={"Authorization": f"Bearer {access_token}"},
    )
    assert confirm_response.status_code == HTTP_CREATED
    confirm_body = confirm_response.json()
    assert confirm_body["enabled"] is True
    return cast("str", enable_body["secret"]), tuple(cast("list[str]", confirm_body["recovery_codes"]))


def test_totp_extension_fails_closed_without_used_token_store() -> None:
    """The extension-mounted TOTP controller preserves replay-store fail-closed startup behavior."""
    with pytest.raises(ConfigurationError, match="used_tokens_store is required"):
        _build_app(totp_config=_build_totp_config(used_tokens_store=None))


def test_totp_extension_validates_pending_secret_for_production() -> None:
    """The extension path keeps production secret validation for pending-login tokens."""
    with pytest.raises(ConfigurationError, match="totp_pending_secret must be at least 32 characters"):
        _build_app(
            totp_config=_build_totp_config(
                pending_secret="short",
                used_tokens_store=_totp_mod.InMemoryUsedTotpCodeStore(),
            ),
        )


@pytest.mark.filterwarnings("ignore::litestar_auth.totp.SecurityWarning")
async def test_totp_extension_mounts_routes_and_preserves_totp_flow(monkeypatch: pytest.MonkeyPatch) -> None:
    """TOTP mounted by ``totp_config`` supports the real enable, verify, recovery, step-up, and disable flow."""
    captured_controllers: list[object] = []
    app, user_db = _build_app(
        totp_config=_build_totp_config(used_tokens_store=_totp_mod.InMemoryUsedTotpCodeStore()),
        captured_controllers=captured_controllers,
    )
    paths = cast("Any", app.openapi_schema.paths)
    assert {
        "/auth/2fa/enable",
        "/auth/2fa/enable/confirm",
        "/auth/2fa/disable",
        "/auth/2fa/verify",
        "/auth/2fa/recovery-codes/regenerate",
    }.issubset(paths)
    totp_controller = next(
        controller for controller in captured_controllers if getattr(controller, "path", "") == "/auth/2fa"
    )
    assert _is_litestar_auth_route_handler(totp_controller) is False

    fixed_counter = 123_456
    monkeypatch.setattr(_totp_primitive, "_current_counter", lambda: fixed_counter)
    async with AsyncTestClient(app=app) as client:
        login_response = await client.post(
            "/auth/login",
            json={"identifier": "user@example.com", "password": "correct-password"},
        )
        assert login_response.status_code == HTTP_CREATED
        access_token = login_response.json()["access_token"]

        secret, recovery_codes = await _enable_totp(client, access_token=access_token)
        assert recovery_codes
        assert next(iter(user_db.users_by_id.values())).totp_secret is not None

        pending_response = await client.post(
            "/auth/login",
            json={"identifier": "user@example.com", "password": "correct-password"},
        )
        assert pending_response.status_code == HTTP_ACCEPTED
        assert pending_response.json()["totp_required"] is True

        fixed_counter += 1
        verify_response = await client.post(
            "/auth/2fa/verify",
            json={
                "pending_token": pending_response.json()["pending_token"],
                "code": _totp_primitive._generate_totp_code(secret, fixed_counter),
            },
        )
        assert verify_response.status_code == HTTP_CREATED
        verified_access_token = verify_response.json()["access_token"]

        fixed_counter += 1
        regenerate_response = await client.post(
            "/auth/2fa/recovery-codes/regenerate",
            json={
                "current_password": "correct-password",
                "totp_code": _totp_primitive._generate_totp_code(secret, fixed_counter),
            },
            headers={"Authorization": f"Bearer {verified_access_token}"},
        )
        assert regenerate_response.status_code == HTTP_CREATED
        assert tuple(regenerate_response.json()["recovery_codes"]) != recovery_codes

        fixed_counter += 1
        disable_response = await client.post(
            "/auth/2fa/disable",
            json={"code": _totp_primitive._generate_totp_code(secret, fixed_counter)},
            headers={"Authorization": f"Bearer {verified_access_token}"},
        )
        assert disable_response.status_code == HTTP_CREATED
        assert next(iter(user_db.users_by_id.values())).totp_secret is None

        fixed_counter += 1
        monkeypatch.setattr(_totp_primitive, "_current_counter", lambda: fixed_counter)
        second_secret, _ = await _enable_totp(client, access_token=verified_access_token)

        missing_stepup_response = await client.patch(
            "/users/me",
            json={"email": "updated@example.com", "current_password": "correct-password"},
            headers={"Authorization": f"Bearer {verified_access_token}"},
        )
        assert missing_stepup_response.status_code == HTTP_FORBIDDEN
        assert missing_stepup_response.json()["extra"]["code"] == ErrorCode.TOTP_STEPUP_REQUIRED

        fixed_counter += 1
        accepted_stepup_response = await client.patch(
            "/users/me",
            json={
                "email": "updated@example.com",
                "current_password": "correct-password",
                "totp_code": _totp_primitive._generate_totp_code(second_secret, fixed_counter),
            },
            headers={"Authorization": f"Bearer {verified_access_token}"},
        )
        assert accepted_stepup_response.status_code == HTTP_OK
        assert accepted_stepup_response.json()["email"] == "updated@example.com"
