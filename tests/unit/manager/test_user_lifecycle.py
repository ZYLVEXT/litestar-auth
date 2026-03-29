"""Tests for ``UserLifecycleService``."""

from __future__ import annotations

import importlib
import logging
from dataclasses import dataclass, replace
from unittest.mock import AsyncMock, Mock, patch
from uuid import uuid4

import pytest

import litestar_auth._manager.user_lifecycle as user_lifecycle_module
import litestar_auth.manager as manager_module
from litestar_auth._manager.user_lifecycle import UserLifecycleService
from litestar_auth._manager.user_policy import UserPolicy
from litestar_auth.exceptions import (
    InactiveUserError,
    InvalidPasswordError,
    UnverifiedUserError,
    UserAlreadyExistsError,
    UserNotExistsError,
)
from litestar_auth.password import PasswordHelper
from litestar_auth.schemas import UserCreate, UserUpdate
from tests._helpers import ExampleUser
from tests.unit import test_manager as test_manager_module
from tests.unit.test_manager import TrackingUserManager

pytestmark = pytest.mark.unit


def test_user_lifecycle_module_executes_under_coverage() -> None:
    """Reload the module in-test so coverage records module and class definitions."""
    reloaded_module = importlib.reload(user_lifecycle_module)
    manager_module.SAFE_FIELDS = reloaded_module.SAFE_FIELDS
    manager_module._PRIVILEGED_FIELDS = reloaded_module.PRIVILEGED_FIELDS
    test_manager_module.SAFE_FIELDS = reloaded_module.SAFE_FIELDS
    test_manager_module.PRIVILEGED_FIELDS = reloaded_module.PRIVILEGED_FIELDS

    assert reloaded_module.UserLifecycleService.__name__ == UserLifecycleService.__name__


def _build_user(
    password_helper: PasswordHelper,
    *,
    email: str = "user@example.com",
    username: str = "existing-user",
) -> ExampleUser:
    """Return a test user with a hashed password."""
    return ExampleUser(
        id=uuid4(),
        email=email,
        username=username,
        hashed_password=password_helper.hash("test-password"),
    )


@dataclass(slots=True)
class _Backend:
    strategy: object


async def test_create_normalizes_email_hashes_password_and_runs_register_hook() -> None:
    """create() normalizes email input before persisting and dispatching hooks."""
    user_db = AsyncMock()
    password_helper = PasswordHelper()
    manager = TrackingUserManager(user_db, password_helper)
    service = UserLifecycleService(manager)
    created_user = _build_user(password_helper, email="user@example.com")
    user_db.get_by_email.return_value = None
    user_db.create.return_value = created_user

    result = await service.create({"email": "  USER@Example.COM  ", "password": "test-password"})

    assert result is created_user
    user_db.get_by_email.assert_awaited_once_with("user@example.com")
    create_payload = user_db.create.await_args.args[0]
    assert create_payload["email"] == "user@example.com"
    assert "password" not in create_payload
    assert password_helper.verify("test-password", create_payload["hashed_password"]) is True
    assert len(manager.registration_events) == 1
    registered_user, token = manager.registration_events[0]
    assert registered_user is created_user
    assert isinstance(token, str)


async def test_create_rejects_duplicate_email_after_normalization() -> None:
    """create() detects duplicate users using the normalized email address."""
    user_db = AsyncMock()
    password_helper = PasswordHelper()
    manager = TrackingUserManager(user_db, password_helper)
    service = UserLifecycleService(manager)
    user_db.get_by_email.return_value = _build_user(password_helper, email="duplicate@example.com")

    with pytest.raises(UserAlreadyExistsError):
        await service.create({"email": " DUPLICATE@example.com ", "password": "test-password"})

    user_db.create.assert_not_awaited()
    assert manager.registration_events == []


async def test_create_with_policy_uses_policy_helpers_instead_of_manager_privates() -> None:
    """create() should use the injected policy helpers when provided."""
    user_db = AsyncMock()
    password_helper = PasswordHelper()
    manager = TrackingUserManager(user_db, password_helper)
    service = UserLifecycleService(manager, policy=UserPolicy(password_helper=password_helper))
    created_user = _build_user(password_helper, email="policy@example.com")
    user_db.get_by_email.return_value = None
    user_db.create.return_value = created_user

    with (
        patch.object(manager, "_normalize_email", side_effect=AssertionError("manager normalize should not run")),
        patch.object(manager, "_validate_password", side_effect=AssertionError("manager validate should not run")),
    ):
        result = await service.create(UserCreate(email="policy@example.com", password="test-password"))

    assert result is created_user
    create_payload = user_db.create.await_args.args[0]
    assert password_helper.verify("test-password", create_payload["hashed_password"]) is True


async def test_list_users_delegates_to_user_db() -> None:
    """list_users() should proxy pagination parameters unchanged."""
    user_db = AsyncMock()
    password_helper = PasswordHelper()
    manager = TrackingUserManager(user_db, password_helper)
    service = UserLifecycleService(manager)
    users = [_build_user(password_helper)]
    user_db.list_users.return_value = (users, 1)

    result = await service.list_users(offset=2, limit=5)

    assert result == (users, 1)
    user_db.list_users.assert_awaited_once_with(offset=2, limit=5)


async def test_get_delegates_to_user_db() -> None:
    """get() should proxy identifier lookups to the user database."""
    user_db = AsyncMock()
    password_helper = PasswordHelper()
    manager = TrackingUserManager(user_db, password_helper)
    service = UserLifecycleService(manager)
    user = _build_user(password_helper)
    user_db.get.return_value = user

    result = await service.get(user.id)

    assert result is user
    user_db.get.assert_awaited_once_with(user.id)


async def test_authenticate_username_mode_returns_none_for_blank_lookup() -> None:
    """authenticate() skips the database lookup when the normalized username is blank."""
    user_db = AsyncMock()
    password_helper = PasswordHelper()
    manager = TrackingUserManager(user_db, password_helper)
    service = UserLifecycleService(manager)

    result = await service.authenticate(
        "   ",
        "test-password",
        login_identifier="username",
        dummy_hash=password_helper.hash("dummy-password"),
        logger=Mock(),
    )

    assert result is None
    user_db.get_by_field.assert_not_awaited()


async def test_authenticate_logs_password_upgrade_failure_and_preserves_login() -> None:
    """authenticate() logs and continues when hash-upgrade persistence fails."""
    user_db = AsyncMock()
    password_helper = PasswordHelper()
    manager = TrackingUserManager(user_db, password_helper)
    service = UserLifecycleService(manager)
    user = _build_user(password_helper, username="user-name")
    logger = Mock(spec=logging.Logger)
    user_db.get_by_field.return_value = user
    user_db.update.side_effect = RuntimeError("db unavailable")

    with patch.object(password_helper, "verify_and_update", return_value=(True, "new-hash")):
        result = await service.authenticate(
            " User-Name ",
            "test-password",
            login_identifier="username",
            dummy_hash="dummy-hash",
            logger=logger,
        )

    assert result is user
    user_db.get_by_field.assert_awaited_once_with("username", "user-name")
    user_db.update.assert_awaited_once_with(user, {"hashed_password": "new-hash"})
    logger.warning.assert_called_once()
    assert logger.warning.call_args.args[0] == "Password hash upgrade skipped (login succeeded)"
    assert logger.warning.call_args.kwargs["extra"]["event"] == "password_upgrade_skipped"
    assert logger.warning.call_args.kwargs["extra"]["user_id"] == str(user.id)


async def test_update_email_change_resets_verification_invalidates_tokens_and_requests_verify() -> None:
    """update() should reset verification and invalidate sessions on email changes."""
    user_db = AsyncMock()
    password_helper = PasswordHelper()
    invalidator = AsyncMock()
    manager = TrackingUserManager(
        user_db,
        password_helper,
        backends=(_Backend(strategy=type("InvalidateStrategy", (), {"invalidate_all_tokens": invalidator})()),),
    )
    service = UserLifecycleService(manager)
    user = replace(_build_user(password_helper), is_verified=True)
    updated_user = replace(user, email="updated@example.com", is_verified=False)
    user_db.get_by_email.return_value = None
    user_db.update.return_value = updated_user

    result = await service.update({"email": " Updated@example.com "}, user)

    assert result is updated_user
    user_db.update.assert_awaited_once_with(
        user,
        {"email": "updated@example.com", "is_verified": False},
    )
    invalidator.assert_awaited_once_with(updated_user)
    assert len(manager.request_verify_events) == 1
    verify_user, token = manager.request_verify_events[0]
    assert verify_user is updated_user
    assert isinstance(token, str)
    assert manager.after_update_events == [(updated_user, {"email": "updated@example.com", "is_verified": False})]


async def test_update_password_change_hashes_password_invalidates_tokens_and_runs_hook() -> None:
    """update() hashes new passwords and invalidates existing sessions."""
    user_db = AsyncMock()
    password_helper = PasswordHelper()
    invalidator = AsyncMock()
    manager = TrackingUserManager(
        user_db,
        password_helper,
        backends=(_Backend(strategy=type("InvalidateStrategy", (), {"invalidate_all_tokens": invalidator})()),),
    )
    service = UserLifecycleService(manager)
    user = _build_user(password_helper)
    updated_user = replace(user)
    user_db.update.return_value = updated_user

    result = await service.update(UserUpdate(password="new-password"), user)

    assert result is updated_user
    update_payload = user_db.update.await_args.args[1]
    assert "password" not in update_payload
    assert password_helper.verify("new-password", update_payload["hashed_password"]) is True
    invalidator.assert_awaited_once_with(updated_user)
    assert manager.request_verify_events == []
    assert manager.after_update_events == [(updated_user, update_payload)]


async def test_update_rejects_duplicate_email_for_another_user() -> None:
    """update() raises when a different user already owns the target email."""
    user_db = AsyncMock()
    password_helper = PasswordHelper()
    manager = TrackingUserManager(user_db, password_helper)
    service = UserLifecycleService(manager)
    user = _build_user(password_helper, email="user@example.com")
    duplicate_user = _build_user(password_helper, email="taken@example.com")
    user_db.get_by_email.return_value = duplicate_user

    with pytest.raises(UserAlreadyExistsError):
        await service.update({"email": "taken@example.com"}, user)

    user_db.update.assert_not_awaited()
    assert manager.after_update_events == []


async def test_update_allows_same_normalized_email_without_side_effects() -> None:
    """update() should not invalidate tokens when the normalized email is unchanged."""
    user_db = AsyncMock()
    password_helper = PasswordHelper()
    invalidator = AsyncMock()
    manager = TrackingUserManager(
        user_db,
        password_helper,
        backends=(_Backend(strategy=type("InvalidateStrategy", (), {"invalidate_all_tokens": invalidator})()),),
    )
    service = UserLifecycleService(manager)
    user = _build_user(password_helper, email="user@example.com")
    duplicate_self = replace(user)
    updated_user = replace(user)
    user_db.get_by_email.return_value = duplicate_self
    user_db.update.return_value = updated_user

    result = await service.update({"email": " USER@example.com "}, user)

    assert result is updated_user
    user_db.update.assert_awaited_once_with(user, {"email": "user@example.com"})
    invalidator.assert_not_awaited()
    assert manager.request_verify_events == []
    assert manager.after_update_events == [(updated_user, {"email": "user@example.com"})]


async def test_update_returns_original_user_when_no_non_null_changes_exist() -> None:
    """update() should treat None-valued fields as absent."""
    user_db = AsyncMock()
    password_helper = PasswordHelper()
    manager = TrackingUserManager(user_db, password_helper)
    service = UserLifecycleService(manager)
    user = _build_user(password_helper)

    result = await service.update({"email": None, "password": None}, user)

    assert result is user
    user_db.update.assert_not_awaited()


def test_non_null_update_dict_filters_none_values() -> None:
    """_non_null_update_dict() drops unset values from mapping inputs."""
    assert UserLifecycleService._non_null_update_dict({"email": "user@example.com", "password": None}) == {
        "email": "user@example.com",
    }


def test_apply_password_update_returns_false_when_password_missing() -> None:
    """_apply_password_update() is a no-op without a password field."""
    user_db = AsyncMock()
    password_helper = PasswordHelper()
    manager = TrackingUserManager(user_db, password_helper)
    service = UserLifecycleService(manager)
    update_dict = {"email": "user@example.com"}

    changed = service._apply_password_update(update_dict)

    assert changed is False
    assert update_dict == {"email": "user@example.com"}


def test_require_account_state_raises_for_inactive_and_unverified_users() -> None:
    """require_account_state() delegates to the shared user policy checks."""
    user = ExampleUser(id=uuid4(), is_active=False, is_verified=False)
    verified_required_user = replace(user, is_active=True)

    with pytest.raises(InactiveUserError):
        UserLifecycleService.require_account_state(user)
    with pytest.raises(UnverifiedUserError):
        UserLifecycleService.require_account_state(verified_required_user, require_verified=True)


async def test_delete_calls_hooks_and_rejects_missing_users() -> None:
    """delete() should execute lifecycle hooks only for existing users."""
    user_db = AsyncMock()
    password_helper = PasswordHelper()
    manager = TrackingUserManager(user_db, password_helper)
    service = UserLifecycleService(manager)
    user = _build_user(password_helper)
    missing_user_id = uuid4()
    user_db.get.side_effect = [user, None]

    assert await service.delete(user.id) is None

    assert manager.before_delete_users == [user]
    assert manager.deleted_users == [user]
    user_db.delete.assert_awaited_once_with(user.id)
    with pytest.raises(UserNotExistsError):
        await service.delete(missing_user_id)


def test_helper_methods_fall_back_to_manager_when_policy_missing() -> None:
    """Helper methods should delegate to manager-private compatibility shims without a policy."""
    user_db = AsyncMock()
    password_helper = PasswordHelper()
    manager = TrackingUserManager(user_db, password_helper)
    service = UserLifecycleService(manager)

    with (
        patch.object(manager, "_normalize_email", return_value="normalized@example.com") as normalize_email,
        patch.object(manager, "_normalize_username_lookup", return_value="normalized-user") as normalize_username,
        patch.object(manager, "_validate_password") as validate_password,
        patch.object(manager.password_helper, "hash", return_value="hashed-value") as hash_password,
        patch.object(manager.password_helper, "verify_and_update", return_value=(True, "new-hash")) as verify_update,
    ):
        assert service._normalize_email(" raw@example.com ") == "normalized@example.com"
        assert service._normalize_username_lookup(" RawUser ") == "normalized-user"
        service._validate_password("secret-password")
        assert service._hash_password("secret-password") == "hashed-value"
        assert service._verify_and_update_password("secret-password", "stored-hash") == (True, "new-hash")

    normalize_email.assert_called_once_with(" raw@example.com ")
    normalize_username.assert_called_once_with(" RawUser ")
    validate_password.assert_called_once_with("secret-password")
    hash_password.assert_called_once_with("secret-password")
    verify_update.assert_called_once_with("secret-password", "stored-hash")


def test_policy_helper_methods_are_used_for_validation_and_hashing() -> None:
    """Helper methods should delegate to the injected policy object when present."""
    user_db = AsyncMock()
    password_helper = PasswordHelper()
    manager = TrackingUserManager(user_db, password_helper)
    policy = UserPolicy(password_helper=password_helper)
    service = UserLifecycleService(manager, policy=policy)

    with patch.object(policy, "validate_password") as validate_password:
        assert service._normalize_email("  User@Example.COM ") == "user@example.com"
        assert service._normalize_username_lookup("  UserName ") == "username"
        service._validate_password("secret-password")

    validate_password.assert_called_once_with("secret-password")
    hashed_password = service._hash_password("secret-password")
    verified, new_hash = service._verify_and_update_password("secret-password", hashed_password)
    assert verified is True
    assert new_hash is None or isinstance(new_hash, str)


def test_apply_password_update_propagates_validation_errors() -> None:
    """Weak passwords should raise before mutation of the persistence payload."""
    user_db = AsyncMock()
    password_helper = PasswordHelper()
    manager = TrackingUserManager(user_db, password_helper)
    service = UserLifecycleService(manager)
    update_dict = {"password": "short"}

    with pytest.raises(InvalidPasswordError):
        service._apply_password_update(update_dict)

    assert update_dict == {"password": "short"}
