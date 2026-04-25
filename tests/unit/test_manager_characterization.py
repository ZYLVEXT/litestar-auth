"""Characterization tests for the public BaseUserManager facade."""

from __future__ import annotations

import base64
from dataclasses import dataclass, replace
from types import ModuleType
from typing import Any, cast
from unittest.mock import AsyncMock
from uuid import UUID, uuid4

import pytest

import litestar_auth.manager as manager_module
from litestar_auth.exceptions import InvalidResetPasswordTokenError, InvalidVerifyTokenError
from litestar_auth.manager import ENCRYPTED_TOTP_SECRET_PREFIX, BaseUserManager, UserManagerSecurity
from litestar_auth.password import PasswordHelper
from litestar_auth.schemas import AdminUserUpdate, UserCreate
from tests._helpers import ExampleUser

pytestmark = pytest.mark.unit

VERIFY_SECRET = "verify-secret-1234567890-1234567890"
RESET_SECRET = "reset-secret-1234567890-1234567890"
TOTP_SECRET_KEY = "test-totp-secret-key-123456789012345="


class CharacterizationManager(BaseUserManager[ExampleUser, UUID]):
    """Concrete manager that records observable lifecycle events."""

    def __init__(
        self,
        user_db: AsyncMock,
        *,
        totp_secret_key: str | None = None,
        backends: tuple[object, ...] = (),
    ) -> None:
        """Create a manager with stable secrets and UUID parsing."""
        super().__init__(
            user_db,
            password_helper=PasswordHelper(),
            security=UserManagerSecurity[UUID](
                verification_token_secret=VERIFY_SECRET,
                reset_password_token_secret=RESET_SECRET,
                totp_secret_key=totp_secret_key,
                id_parser=UUID,
            ),
            backends=backends,
        )
        self.events: list[tuple[str, UUID]] = []
        self.verify_tokens: list[str] = []
        self.reset_tokens: list[str] = []

    async def on_after_register(self, user: ExampleUser, token: str) -> None:
        """Record the registration lifecycle event."""
        self.events.append(("register", user.id))
        self.verify_tokens.append(token)

    async def on_after_verify(self, user: ExampleUser) -> None:
        """Record the verification lifecycle event."""
        self.events.append(("verify", user.id))

    async def on_after_request_verify_token(self, user: ExampleUser | None, token: str | None) -> None:
        """Record the verification-token request lifecycle event."""
        if user is not None and token is not None:
            self.events.append(("request_verify", user.id))
            self.verify_tokens.append(token)

    async def on_after_forgot_password(self, user: ExampleUser | None, token: str | None) -> None:
        """Record the forgot-password lifecycle event."""
        if user is not None and token is not None:
            self.events.append(("forgot_password", user.id))
            self.reset_tokens.append(token)

    async def on_after_reset_password(self, user: ExampleUser) -> None:
        """Record the reset-password lifecycle event."""
        self.events.append(("reset_password", user.id))

    async def on_after_update(self, user: ExampleUser, update_dict: dict[str, Any]) -> None:
        """Record update payloads without exposing internal helper details."""
        del update_dict
        self.events.append(("update", user.id))

    async def on_before_delete(self, user: ExampleUser) -> None:
        """Record the pre-delete lifecycle event."""
        self.events.append(("before_delete", user.id))

    async def on_after_delete(self, user: ExampleUser) -> None:
        """Record the post-delete lifecycle event."""
        self.events.append(("after_delete", user.id))


class FakeInvalidTokenError(Exception):
    """Fake cryptography InvalidToken replacement for deterministic tests."""


class FakeFernet:
    """Minimal Fernet-compatible implementation for unit tests."""

    def __init__(self, key: bytes) -> None:
        """Store the signing key prefix."""
        self.prefix = b"enc:" + key[:8] + b":"

    def encrypt(self, data: bytes) -> bytes:
        """Encode data into a deterministic token.

        Returns:
            Base64-encoded token bytes that preserve the input payload.
        """
        return base64.urlsafe_b64encode(self.prefix + data)

    def decrypt(self, token: bytes) -> bytes:
        """Decode a deterministic token back into its payload.

        Returns:
            The original payload bytes.

        Raises:
            FakeInvalidTokenError: If the token was not produced for this key.
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


def _build_user(
    password_helper: PasswordHelper,
    *,
    email: str = "user@example.com",
    password: str = "test-password",
) -> ExampleUser:
    """Create a test user with a hashed password.

    Returns:
        An example user with a stored password hash.
    """
    return ExampleUser(id=uuid4(), email=email, hashed_password=password_helper.hash(password))


async def test_manager_crud_facade_characterization() -> None:
    """Create, read, list, update, and delete stay wired through the public facade."""
    user_db = AsyncMock()
    manager = CharacterizationManager(user_db)
    password_helper = manager.password_helper
    created_user = _build_user(password_helper)
    updated_user = replace(
        created_user,
        email="updated@example.com",
        hashed_password=password_helper.hash("new-password"),
        is_verified=False,
    )
    listed_users = [created_user, _build_user(password_helper, email="second@example.com")]
    user_db.get_by_email.side_effect = [None, None]
    user_db.create.return_value = created_user
    user_db.get.side_effect = [updated_user, created_user]
    user_db.list_users.return_value = (listed_users, len(listed_users))
    user_db.update.return_value = updated_user

    created = await manager.create(UserCreate(email="USER@example.com", password="test-password"))
    fetched = await manager.get(updated_user.id)
    listed, total = await manager.list_users(offset=1, limit=2)
    updated = await manager.update(
        AdminUserUpdate(email="updated@example.com", password="new-password"),
        created_user,
    )
    await manager.delete(created_user.id)

    assert created is created_user
    assert fetched is updated_user
    assert listed == listed_users
    assert total == len(listed_users)
    assert updated is updated_user
    create_payload = user_db.create.await_args.args[0]
    assert create_payload["email"] == "user@example.com"
    assert "password" not in create_payload
    assert password_helper.verify("test-password", create_payload["hashed_password"]) is True
    user_db.list_users.assert_awaited_once_with(offset=1, limit=2)
    update_payload = user_db.update.await_args_list[0].args[1]
    assert update_payload["email"] == "updated@example.com"
    assert update_payload["is_verified"] is False
    assert "password" not in update_payload
    assert password_helper.verify("new-password", update_payload["hashed_password"]) is True
    user_db.delete.assert_awaited_once_with(created_user.id)
    assert manager.events == [
        ("register", created_user.id),
        ("request_verify", updated_user.id),
        ("update", updated_user.id),
        ("before_delete", created_user.id),
        ("after_delete", created_user.id),
    ]


async def test_manager_verify_and_reset_token_contracts() -> None:
    """Verify and reset tokens preserve the current public manager semantics."""
    user_db = AsyncMock()
    manager = CharacterizationManager(user_db)
    user = _build_user(manager.password_helper)
    verified_user = replace(user, is_verified=True)
    reset_user = replace(verified_user, hashed_password=manager.password_helper.hash("brand-new-password"))
    user_db.get_by_email.return_value = user
    user_db.get.side_effect = [user, user, verified_user]
    user_db.update.side_effect = [verified_user, reset_user]

    verify_token = manager.write_verify_token(user)
    verified = await manager.verify(verify_token)
    await manager.forgot_password(user.email)
    reset_token = manager.reset_tokens[0]
    reset_result = await manager.reset_password(reset_token, "brand-new-password")

    assert verified is verified_user
    assert reset_result is reset_user
    assert manager.events == [
        ("verify", verified_user.id),
        ("forgot_password", user.id),
        ("reset_password", reset_user.id),
    ]

    with pytest.raises(InvalidVerifyTokenError, match="already verified"):
        await manager.verify(verify_token)


async def test_security_sensitive_changes_invalidate_existing_reset_tokens() -> None:
    """Password-sensitive reset tokens become unusable after credential changes."""
    user_db = AsyncMock()
    manager = CharacterizationManager(user_db)
    user = _build_user(manager.password_helper)
    user_db.get_by_email.return_value = user

    await manager.forgot_password(user.email)

    changed_user = replace(
        user,
        email="rotated@example.com",
        hashed_password=manager.password_helper.hash("rotated-password"),
    )
    user_db.get.return_value = changed_user

    with pytest.raises(InvalidResetPasswordTokenError):
        await manager.reset_password(manager.reset_tokens[0], "brand-new-password")

    user_db.update.assert_not_awaited()


async def test_security_sensitive_updates_invalidate_attached_auth_backends() -> None:
    """Password and email updates keep backend token invalidation wired through the facade."""
    user_db = AsyncMock()
    manager = CharacterizationManager(user_db)
    user = replace(_build_user(manager.password_helper), is_verified=True)
    updated_user = replace(
        user,
        email="updated@example.com",
        hashed_password=manager.password_helper.hash("new-password"),
        is_verified=False,
    )
    invalidate_all_tokens = AsyncMock()

    @dataclass(slots=True)
    class Backend:
        strategy: object

    manager.backends = (Backend(strategy=type("Strategy", (), {"invalidate_all_tokens": invalidate_all_tokens})()),)
    user_db.get_by_email.return_value = None
    user_db.update.return_value = updated_user

    result = await manager.update(
        AdminUserUpdate(email="updated@example.com", password="new-password"),
        user,
    )

    assert result is updated_user
    invalidate_all_tokens.assert_awaited_once_with(updated_user)
    assert manager.events == [("request_verify", updated_user.id), ("update", updated_user.id)]


async def test_totp_secret_facade_characterization(monkeypatch: pytest.MonkeyPatch) -> None:
    """TOTP secret storage stays observable through set/read manager methods."""
    _install_fake_cryptography(monkeypatch)
    user_db = AsyncMock()
    manager = CharacterizationManager(user_db, totp_secret_key=TOTP_SECRET_KEY)
    user = _build_user(manager.password_helper)
    encrypted_user = replace(user)
    user_db.update.return_value = encrypted_user

    updated_user = await manager.set_totp_secret(user, "JBSWY3DPEHPK3PXP")
    stored_secret = user_db.update.await_args.args[1]["totp_secret"]
    decrypted_secret = await manager.read_totp_secret(stored_secret)

    assert updated_user is encrypted_user
    assert stored_secret.startswith(f"{ENCRYPTED_TOTP_SECRET_PREFIX}v1:default:")
    assert stored_secret != "JBSWY3DPEHPK3PXP"
    assert decrypted_secret == "JBSWY3DPEHPK3PXP"

    with pytest.raises(RuntimeError, match="encrypted at rest"):
        await manager.read_totp_secret("plain-secret")
