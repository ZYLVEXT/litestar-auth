"""Integration tests for direct-manager and controller TOTP secret storage."""

from __future__ import annotations

import asyncio
import base64
from types import ModuleType
from typing import TYPE_CHECKING, Any, cast
from unittest.mock import AsyncMock
from uuid import UUID, uuid4

import pytest
from litestar import Request, get
from litestar.middleware import DefineMiddleware
from litestar.testing import AsyncTestClient

import litestar_auth.manager as manager_module
from litestar_auth._plugin.config import DEFAULT_USER_MANAGER_DEPENDENCY_KEY
from litestar_auth.authentication.authenticator import Authenticator
from litestar_auth.authentication.backend import AuthenticationBackend
from litestar_auth.authentication.middleware import LitestarAuthMiddleware
from litestar_auth.authentication.strategy.jwt import InMemoryJWTDenylistStore
from litestar_auth.authentication.transport.bearer import BearerTransport
from litestar_auth.controllers import create_auth_controller, create_totp_controller
from litestar_auth.manager import ENCRYPTED_TOTP_SECRET_PREFIX, BaseUserManager, UserManagerSecurity
from litestar_auth.password import PasswordHelper
from litestar_auth.totp import (
    InMemoryTotpEnrollmentStore,
    InMemoryUsedTotpCodeStore,
    _current_counter,
    _generate_totp_code,
)
from tests._helpers import auth_middleware_get_request_session, litestar_app_with_user_manager
from tests.integration.conftest import DummySessionMaker, ExampleUser, InMemoryTokenStrategy, InMemoryUserDatabase

if TYPE_CHECKING:
    from litestar import Litestar

pytestmark = [
    pytest.mark.integration,
]

HTTP_CREATED = 201
HTTP_ACCEPTED = 202
TOTP_PENDING_SECRET = "test-totp-pending-secret-thirty-two!"
TOTP_SECRET_KEY = "test-totp-secret-key-123456789012345="


@get("/probe")
async def probe(request: Request[Any, Any, Any]) -> dict[str, str | None]:
    """Return the authenticated email for assertions."""
    await asyncio.sleep(0)
    user = cast("ExampleUser | None", request.user)
    return {"email": user.email if user is not None else None}


class FakeInvalidTokenError(Exception):
    """Fake cryptography token error."""


class FakeFernet:
    """Minimal Fernet-compatible test double."""

    def __init__(self, key: bytes) -> None:
        """Store the signing key prefix."""
        self.prefix = b"enc:" + key[:8] + b":"

    def encrypt(self, data: bytes) -> bytes:
        """Encode data into a deterministic token.

        Returns:
            A token that can be decoded by :meth:`decrypt`.
        """
        return base64.urlsafe_b64encode(self.prefix + data)

    def decrypt(self, token: bytes) -> bytes:
        """Decode and validate a token.

        Returns:
            The original payload bytes.

        Raises:
            FakeInvalidTokenError: If the token does not match this key.
        """
        decoded = base64.urlsafe_b64decode(token)
        if not decoded.startswith(self.prefix):
            raise FakeInvalidTokenError
        return decoded.removeprefix(self.prefix)


def _install_fake_cryptography(monkeypatch: pytest.MonkeyPatch) -> None:
    """Patch the manager module to use a fake cryptography backend."""
    fake_module = cast("Any", ModuleType("cryptography.fernet"))
    fake_module.Fernet = FakeFernet
    fake_module.InvalidToken = FakeInvalidTokenError

    def fake_import_module(name: str) -> ModuleType:
        if name == "cryptography.fernet":
            return fake_module
        msg = name
        raise ImportError(msg)

    monkeypatch.setattr(manager_module.importlib, "import_module", fake_import_module)


def _build_manager(
    user_db: AsyncMock,
    *,
    totp_secret_key: str | None = None,
) -> BaseUserManager[ExampleUser, UUID]:
    """Create a manager with predictable test configuration.

    Returns:
        A configured ``BaseUserManager`` instance.
    """
    password_helper = PasswordHelper()
    return BaseUserManager(
        user_db,
        password_helper=password_helper,
        security=UserManagerSecurity[UUID](
            verification_token_secret="verify-secret-1234567890-1234567890",
            reset_password_token_secret="reset-secret-1234567890-1234567890",
            totp_secret_key=totp_secret_key,
            id_parser=UUID,
        ),
    )


def _build_app() -> tuple[Litestar, InMemoryUserDatabase]:
    """Build a small app that exercises encrypted TOTP controller flow.

    Returns:
        A Litestar app plus its in-memory user database.
    """
    password_helper = PasswordHelper()
    user = ExampleUser(
        id=uuid4(),
        email="user@example.com",
        hashed_password=password_helper.hash("correct-password"),
        is_verified=True,
    )
    user_db = InMemoryUserDatabase([user])
    user_manager = BaseUserManager[ExampleUser, UUID](
        user_db,
        password_helper=password_helper,
        security=UserManagerSecurity[UUID](
            verification_token_secret="verify-secret-1234567890-1234567890",
            reset_password_token_secret="reset-secret-1234567890-1234567890",
            totp_secret_key=TOTP_SECRET_KEY,
            id_parser=UUID,
        ),
    )
    backend = AuthenticationBackend[ExampleUser, UUID](
        name="memory-bearer",
        transport=BearerTransport(),
        strategy=cast("Any", InMemoryTokenStrategy()),
    )
    auth_controller = create_auth_controller(
        backend=backend,
        totp_pending_secret=TOTP_PENDING_SECRET,
    )
    totp_controller = create_totp_controller(
        backend=backend,
        user_manager_dependency_key=DEFAULT_USER_MANAGER_DEPENDENCY_KEY,
        used_tokens_store=InMemoryUsedTotpCodeStore(),
        pending_jti_store=InMemoryJWTDenylistStore(),
        enrollment_store=InMemoryTotpEnrollmentStore(),
        totp_pending_secret=TOTP_PENDING_SECRET,
        totp_secret_key=TOTP_SECRET_KEY,
        totp_enable_requires_password=False,
        id_parser=UUID,
    )
    middleware = DefineMiddleware(
        LitestarAuthMiddleware[ExampleUser, UUID],
        get_request_session=auth_middleware_get_request_session(cast("Any", DummySessionMaker())),
        authenticator_factory=lambda _session: Authenticator([backend], user_manager),
    )
    app = litestar_app_with_user_manager(
        user_manager,
        auth_controller,
        totp_controller,
        probe,
        middleware=[middleware],
    )
    return app, user_db


async def test_set_totp_secret_encrypts_and_read_totp_secret_decrypts(monkeypatch: pytest.MonkeyPatch) -> None:
    """Encrypted TOTP storage round-trips through the manager."""
    _install_fake_cryptography(monkeypatch)
    user_db = AsyncMock()
    manager = _build_manager(user_db, totp_secret_key=TOTP_SECRET_KEY)
    user = ExampleUser(id=uuid4(), email="user@example.com", hashed_password="hashed")
    user_db.update.return_value = user

    await manager.set_totp_secret(user, "JBSWY3DPEHPK3PXP")

    stored_secret = user_db.update.await_args.args[1]["totp_secret"]
    assert stored_secret.startswith(ENCRYPTED_TOTP_SECRET_PREFIX)
    assert stored_secret != "JBSWY3DPEHPK3PXP"
    assert await manager.read_totp_secret(stored_secret) == "JBSWY3DPEHPK3PXP"


async def test_read_totp_secret_rejects_plaintext_persisted_values() -> None:
    """Plaintext persisted TOTP secrets fail closed instead of round-tripping."""
    user_db = AsyncMock()
    plaintext_secret = "JBSWY3DPEHPK3PXP"

    with pytest.raises(RuntimeError, match="encrypted at rest"):
        await _build_manager(user_db).read_totp_secret(plaintext_secret)
    with pytest.raises(RuntimeError, match="encrypted at rest"):
        await _build_manager(user_db, totp_secret_key=TOTP_SECRET_KEY).read_totp_secret(plaintext_secret)


@pytest.mark.parametrize(
    ("totp_secret_key", "expected_key", "encrypts_at_rest"),
    [
        pytest.param(None, "fernet_encrypted", True, id="missing-key"),
        pytest.param(TOTP_SECRET_KEY, "fernet_encrypted", True, id="encrypted"),
    ],
)
def test_direct_base_user_manager_totp_secret_storage_posture_reports_supported_contract(
    *,
    totp_secret_key: str | None,
    expected_key: str,
    encrypts_at_rest: bool,
) -> None:
    """Direct BaseUserManager construction exposes only the encrypted-at-rest contract."""
    manager = _build_manager(
        AsyncMock(),
        totp_secret_key=totp_secret_key,
    )

    posture = manager.totp_secret_storage_posture
    assert posture.key == expected_key
    assert posture.encrypts_at_rest is encrypts_at_rest
    assert posture.requires_explicit_production_opt_in is (totp_secret_key is None)
    if totp_secret_key is None:
        assert posture.production_validation_error is not None
    else:
        assert posture.production_validation_error is None


async def test_read_totp_secret_raises_runtime_error_on_decrypt_failure(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """When decrypt raises InvalidToken, read_totp_secret raises RuntimeError with a clear message."""
    _install_fake_cryptography(monkeypatch)
    user_db = AsyncMock()
    manager = _build_manager(user_db, totp_secret_key=TOTP_SECRET_KEY)
    # Token that decodes to something that does not match FakeFernet's prefix for this key
    bad_token = base64.urlsafe_b64encode(b"wrong:prefix:data")
    encrypted_secret = f"{ENCRYPTED_TOTP_SECRET_PREFIX}{bad_token.decode()}"

    with pytest.raises(RuntimeError, match="TOTP secret decryption failed") as exc_info:
        await manager.read_totp_secret(encrypted_secret)

    assert exc_info.value.__cause__ is not None
    assert type(exc_info.value.__cause__).__name__ == "FakeInvalidTokenError"


async def test_set_totp_secret_raises_readable_error_when_cryptography_missing(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Encrypting secrets without cryptography raises a clear lazy-import error."""
    user_db = AsyncMock()
    manager = _build_manager(user_db, totp_secret_key=TOTP_SECRET_KEY)
    user = ExampleUser(id=uuid4(), email="user@example.com", hashed_password="hashed")

    def fake_import_module(name: str) -> ModuleType:
        msg = name
        raise ImportError(msg)

    monkeypatch.setattr(manager_module.importlib, "import_module", fake_import_module)

    with pytest.raises(ImportError, match="Install litestar-auth\\[totp\\] to use TOTP secret encryption\\."):
        await manager.set_totp_secret(user, "JBSWY3DPEHPK3PXP")


@pytest.mark.filterwarnings("ignore::litestar_auth.totp.SecurityWarning")
async def test_totp_controllers_use_decrypted_secret(monkeypatch: pytest.MonkeyPatch) -> None:
    """Enable, login, and verify work when the stored secret is encrypted."""
    _install_fake_cryptography(monkeypatch)
    app, user_db = _build_app()

    async with AsyncTestClient(app=app) as client:
        login_response = await client.post(
            "/auth/login",
            json={"identifier": "user@example.com", "password": "correct-password"},
        )
        access_token = login_response.json()["access_token"]

        enable_response = await client.post("/auth/2fa/enable", headers={"Authorization": f"Bearer {access_token}"})
        assert enable_response.status_code == HTTP_CREATED
        enable_body = enable_response.json()
        secret = enable_body["secret"]

        # Secret not persisted until confirmation
        stored_user = next(iter(user_db.users_by_id.values()))
        assert stored_user.totp_secret is None

        # Confirm enrollment
        confirm_code = _generate_totp_code(secret, _current_counter())
        confirm_response = await client.post(
            "/auth/2fa/enable/confirm",
            json={"enrollment_token": enable_body["enrollment_token"], "code": confirm_code},
            headers={"Authorization": f"Bearer {access_token}"},
        )
        assert confirm_response.status_code == HTTP_CREATED

        stored_user = next(iter(user_db.users_by_id.values()))
        assert stored_user.totp_secret is not None
        assert stored_user.totp_secret.startswith(ENCRYPTED_TOTP_SECRET_PREFIX)
        assert stored_user.totp_secret != secret

        pending_response = await client.post(
            "/auth/login",
            json={"identifier": "user@example.com", "password": "correct-password"},
        )
        assert pending_response.status_code == HTTP_ACCEPTED
        pending_token = pending_response.json()["pending_token"]

        verify_response = await client.post(
            "/auth/2fa/verify",
            json={"pending_token": pending_token, "code": _generate_totp_code(secret, _current_counter())},
        )
        assert verify_response.status_code == HTTP_CREATED
        assert "access_token" in verify_response.json()
