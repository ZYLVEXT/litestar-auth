"""Tests for ``AccountTokensService`` (account token flows)."""

from __future__ import annotations

import logging
import runpy
from dataclasses import replace
from datetime import timedelta
from pathlib import Path
from unittest.mock import AsyncMock, patch

import jwt
import pytest

import litestar_auth._manager.account_tokens as account_tokens_module
from litestar_auth.exceptions import InvalidResetPasswordTokenError, InvalidVerifyTokenError, UserNotExistsError
from litestar_auth.manager import RESET_PASSWORD_TOKEN_AUDIENCE, VERIFY_TOKEN_AUDIENCE
from litestar_auth.manager import logger as manager_logger
from litestar_auth.password import PasswordHelper
from tests.unit.test_manager import TrackingUserManager, _build_user

pytestmark = pytest.mark.unit

EXPECTED_SHA256_HEX_LENGTH = 64


def test_account_tokens_module_executes_under_coverage() -> None:
    """Execute the module source in-test so coverage records module and class execution."""
    module_globals = runpy.run_path(str(Path(account_tokens_module.__file__).resolve()))

    assert (
        module_globals["AccountTokenSecurityService"].__name__
        == account_tokens_module.AccountTokenSecurityService.__name__
    )
    assert module_globals["AccountTokensService"].__name__ == account_tokens_module.AccountTokensService.__name__


async def test_forgot_password_nonexistent_user_uses_dummy_hash_and_calls_hook_with_none() -> None:
    """Unknown email still signs a dummy token before calling the hook with ``None`` values."""
    user_db = AsyncMock()
    password_helper = PasswordHelper()
    manager = TrackingUserManager(user_db, password_helper)
    user_db.get_by_email.return_value = None
    dummy_hash = manager._get_dummy_hash()

    with patch.object(
        manager._account_tokens,
        "write_reset_password_token",
        wraps=manager._account_tokens.write_reset_password_token,
    ) as write_token:
        await manager._account_tokens.forgot_password("Missing@Example.com", dummy_hash=dummy_hash)

    user_db.get_by_email.assert_awaited_once_with("missing@example.com")
    write_token.assert_called_once_with(None, dummy_hash=dummy_hash)
    assert len(manager.forgot_password_events) == 1
    assert manager.forgot_password_events[0] == (None, None)


async def test_forgot_password_existing_user_calls_hook_with_valid_reset_token() -> None:
    """Existing users receive a reset token bound to their current password fingerprint."""
    user_db = AsyncMock()
    password_helper = PasswordHelper()
    manager = TrackingUserManager(user_db, password_helper)
    user = _build_user(password_helper, email="user@example.com")
    user_db.get_by_email.return_value = user

    await manager._account_tokens.forgot_password("User@Example.com", dummy_hash=manager._get_dummy_hash())

    user_db.get_by_email.assert_awaited_once_with("user@example.com")
    assert len(manager.forgot_password_events) == 1
    event_user, token = manager.forgot_password_events[0]
    assert event_user is user
    assert isinstance(token, str)

    payload = jwt.decode(
        token,
        manager.reset_password_token_secret.get_secret_value(),
        algorithms=["HS256"],
        audience=RESET_PASSWORD_TOKEN_AUDIENCE,
    )
    assert payload["sub"] == str(user.id)
    assert payload["password_fingerprint"] == manager.tokens.password_fingerprint(user.hashed_password)


@pytest.mark.parametrize("verified_state", ["unverified", "verified"])
async def test_request_verify_token_only_emits_hook_for_unverified_users(verified_state: str) -> None:
    """Verification-token requests are no-ops for verified or missing accounts."""
    user_db = AsyncMock()
    password_helper = PasswordHelper()
    manager = TrackingUserManager(user_db, password_helper)
    user = replace(_build_user(password_helper), is_verified=verified_state == "verified")
    user_db.get_by_email.return_value = user

    await manager._account_tokens.request_verify_token("User@Example.com")

    user_db.get_by_email.assert_awaited_once_with("user@example.com")
    if verified_state == "verified":
        assert manager.request_verify_events == []
        return

    assert len(manager.request_verify_events) == 1
    event_user, token = manager.request_verify_events[0]
    assert event_user is user
    decoded_subject = manager._account_token_security.read_token_subject(
        token,
        secret=manager.verification_token_secret.get_secret_value(),
        audience=VERIFY_TOKEN_AUDIENCE,
        invalid_token_error=InvalidVerifyTokenError,
    )
    assert decoded_subject == user.id


async def test_request_verify_token_missing_user_is_noop() -> None:
    """Unknown email does not generate a verification event."""
    user_db = AsyncMock()
    password_helper = PasswordHelper()
    manager = TrackingUserManager(user_db, password_helper)
    user_db.get_by_email.return_value = None

    await manager._account_tokens.request_verify_token("missing@example.com")

    user_db.get_by_email.assert_awaited_once_with("missing@example.com")
    assert manager.request_verify_events == []


async def test_verify_marks_user_verified_and_calls_hook() -> None:
    """Verification decodes the token, updates the user, and triggers the post-verify hook."""
    user_db = AsyncMock()
    password_helper = PasswordHelper()
    manager = TrackingUserManager(user_db, password_helper)
    user = _build_user(password_helper)
    verified_user = replace(user, is_verified=True)
    token = manager._account_tokens.write_verify_token(user)
    user_db.get.return_value = user
    user_db.update.return_value = verified_user

    result = await manager._account_tokens.verify(token)

    assert result is verified_user
    user_db.get.assert_awaited_once_with(user.id)
    user_db.update.assert_awaited_once_with(user, {"is_verified": True})
    assert manager.verified_users == [verified_user]


async def test_verify_rejects_already_verified_user() -> None:
    """Verification tokens cannot be reused for users that are already verified."""
    user_db = AsyncMock()
    password_helper = PasswordHelper()
    manager = TrackingUserManager(user_db, password_helper)
    user = replace(_build_user(password_helper), is_verified=True)
    token = manager._account_tokens.write_verify_token(user)
    user_db.get.return_value = user

    with pytest.raises(InvalidVerifyTokenError, match="already verified"):
        await manager._account_tokens.verify(token)

    user_db.update.assert_not_awaited()
    assert manager.verified_users == []


async def test_reset_password_updates_hash_invalidates_tokens_and_calls_hook() -> None:
    """Resetting with a valid token rehashes the password and runs the side effects."""
    user_db = AsyncMock()
    password_helper = PasswordHelper()
    manager = TrackingUserManager(user_db, password_helper)
    user = _build_user(password_helper)
    updated_user = replace(user, hashed_password=password_helper.hash("new-password-123"))
    token = manager._account_tokens.write_reset_password_token(user, dummy_hash=manager._get_dummy_hash())
    user_db.get.return_value = user
    user_db.update.return_value = updated_user

    with patch.object(manager, "_invalidate_all_tokens", new_callable=AsyncMock) as invalidate_all_tokens:
        result = await manager._account_tokens.reset_password(token, "new-password-123")

        assert result is updated_user
        user_db.get.assert_awaited_once_with(user.id)
        user_db.update.assert_awaited_once()
        update_payload = user_db.update.await_args.args[1]
        assert password_helper.verify("new-password-123", update_payload["hashed_password"]) is True
        assert update_payload["hashed_password"] != user.hashed_password
        invalidate_all_tokens.assert_awaited_once_with(updated_user)
        assert manager.reset_users == [updated_user]


async def test_reset_password_rejects_expired_token() -> None:
    """Expired reset tokens are rejected before any password mutation occurs."""
    user_db = AsyncMock()
    password_helper = PasswordHelper()
    manager = TrackingUserManager(user_db, password_helper)
    user = _build_user(password_helper)
    token = manager._account_tokens.write_user_token(
        user,
        secret=manager.reset_password_token_secret.get_secret_value(),
        audience=RESET_PASSWORD_TOKEN_AUDIENCE,
        lifetime=timedelta(seconds=-1),
    )

    with pytest.raises(InvalidResetPasswordTokenError):
        await manager._account_tokens.reset_password(token, "new-password-123")

    user_db.get.assert_not_awaited()
    user_db.update.assert_not_awaited()


async def test_reset_password_rejects_inactive_user() -> None:
    """Inactive accounts cannot reset their password even with a valid token."""
    user_db = AsyncMock()
    password_helper = PasswordHelper()
    manager = TrackingUserManager(user_db, password_helper)
    user = replace(_build_user(password_helper), is_active=False)
    token = manager._account_tokens.write_reset_password_token(user, dummy_hash=manager._get_dummy_hash())
    user_db.get.return_value = user

    with pytest.raises(InvalidResetPasswordTokenError):
        await manager._account_tokens.reset_password(token, "new-password-123")

    user_db.update.assert_not_awaited()


async def test_reset_password_rejects_token_without_password_fingerprint() -> None:
    """Reset tokens missing the password fingerprint claim are invalid."""
    user_db = AsyncMock()
    password_helper = PasswordHelper()
    manager = TrackingUserManager(user_db, password_helper)
    user = _build_user(password_helper)
    token = manager._account_tokens.write_user_token(
        user,
        secret=manager.reset_password_token_secret.get_secret_value(),
        audience=RESET_PASSWORD_TOKEN_AUDIENCE,
        lifetime=manager.reset_password_token_lifetime,
        extra_claims={"password_fingerprint": None},
    )
    user_db.get.return_value = user

    with pytest.raises(InvalidResetPasswordTokenError):
        await manager._account_tokens.reset_password(token, "new-password-123")

    user_db.update.assert_not_awaited()


async def test_reset_password_rejects_stale_password_fingerprint() -> None:
    """Changing the stored password invalidates previously issued reset tokens."""
    user_db = AsyncMock()
    password_helper = PasswordHelper()
    manager = TrackingUserManager(user_db, password_helper)
    original_user = _build_user(password_helper)
    current_user = replace(original_user, hashed_password=password_helper.hash("changed-password-123"))
    token = manager._account_tokens.write_reset_password_token(
        original_user,
        dummy_hash=manager._get_dummy_hash(),
    )
    user_db.get.return_value = current_user

    with pytest.raises(InvalidResetPasswordTokenError):
        await manager._account_tokens.reset_password(token, "new-password-123")

    user_db.update.assert_not_awaited()


@pytest.mark.parametrize(
    ("token", "audience"),
    [
        pytest.param("not-a-jwt", RESET_PASSWORD_TOKEN_AUDIENCE, id="malformed"),
        pytest.param(None, RESET_PASSWORD_TOKEN_AUDIENCE, id="wrong-audience"),
    ],
)
def test_decode_token_rejects_malformed_or_wrong_audience_tokens(
    token: str | None,
    audience: str,
    caplog: pytest.LogCaptureFixture,
) -> None:
    """Decode failures raise the configured invalid-token error and emit a warning."""
    user_db = AsyncMock()
    password_helper = PasswordHelper()
    manager = TrackingUserManager(user_db, password_helper)
    user = _build_user(password_helper)
    encoded_token = token or manager._account_tokens.write_verify_token(user)

    with caplog.at_level(logging.WARNING, logger=manager_logger.name), pytest.raises(InvalidVerifyTokenError):
        manager._account_token_security.decode_token(
            encoded_token,
            secret=manager.verification_token_secret.get_secret_value(),
            audience=audience,
            invalid_token_error=InvalidVerifyTokenError,
        )

    assert [getattr(record, "event", None) for record in caplog.records] == ["token_validation_failed"]


def test_read_token_subject_supports_string_ids_when_id_parser_is_none() -> None:
    """Token subjects can be returned verbatim when the manager does not parse IDs."""
    user_db = AsyncMock()
    password_helper = PasswordHelper()
    manager = TrackingUserManager(user_db, password_helper)
    manager.id_parser = None
    token = account_tokens_module.AccountTokenSecurityService.write_token_subject(
        subject="user-123",
        secret=manager.verification_token_secret.get_secret_value(),
        audience=VERIFY_TOKEN_AUDIENCE,
        lifetime=manager.verification_token_lifetime,
    )

    subject = manager._account_token_security.read_token_subject(
        token,
        secret=manager.verification_token_secret.get_secret_value(),
        audience=VERIFY_TOKEN_AUDIENCE,
        invalid_token_error=InvalidVerifyTokenError,
    )

    assert subject == "user-123"


@pytest.mark.parametrize(
    ("subject", "expected_error"),
    [
        pytest.param("", InvalidVerifyTokenError, id="empty-subject"),
        pytest.param("not-a-uuid", InvalidResetPasswordTokenError, id="invalid-uuid"),
    ],
)
def test_read_token_subject_rejects_invalid_subjects(
    subject: str,
    expected_error: type[InvalidVerifyTokenError | InvalidResetPasswordTokenError],
    caplog: pytest.LogCaptureFixture,
) -> None:
    """Subject validation rejects empty and unparsable identifiers."""
    user_db = AsyncMock()
    password_helper = PasswordHelper()
    manager = TrackingUserManager(user_db, password_helper)
    token = account_tokens_module.AccountTokenSecurityService.write_token_subject(
        subject=subject,
        secret=manager.reset_password_token_secret.get_secret_value(),
        audience=RESET_PASSWORD_TOKEN_AUDIENCE,
        lifetime=manager.reset_password_token_lifetime,
    )

    with caplog.at_level(logging.WARNING, logger=manager_logger.name), pytest.raises(expected_error):
        manager._account_token_security.read_token_subject(
            token,
            secret=manager.reset_password_token_secret.get_secret_value(),
            audience=RESET_PASSWORD_TOKEN_AUDIENCE,
            invalid_token_error=expected_error,
        )

    assert [getattr(record, "event", None) for record in caplog.records] == ["token_validation_failed"]


async def test_get_user_from_token_raises_when_subject_user_is_missing() -> None:
    """Lookup misses after successful token validation raise ``UserNotExistsError``."""
    user_db = AsyncMock()
    password_helper = PasswordHelper()
    manager = TrackingUserManager(user_db, password_helper)
    user = _build_user(password_helper)
    token = manager._account_tokens.write_verify_token(user)
    user_db.get.return_value = None

    with pytest.raises(UserNotExistsError):
        await manager._account_token_security.get_user_from_token(
            token,
            user_db=user_db,
            secret=manager.verification_token_secret.get_secret_value(),
            audience=VERIFY_TOKEN_AUDIENCE,
            invalid_token_error=InvalidVerifyTokenError,
        )

    user_db.get.assert_awaited_once_with(user.id)


async def test_get_reset_password_context_rejects_missing_user(caplog: pytest.LogCaptureFixture) -> None:
    """Reset-token validation fails when the referenced user no longer exists."""
    user_db = AsyncMock()
    password_helper = PasswordHelper()
    manager = TrackingUserManager(user_db, password_helper)
    user = _build_user(password_helper)
    token = manager._account_tokens.write_reset_password_token(user, dummy_hash=manager._get_dummy_hash())
    user_db.get.return_value = None

    with caplog.at_level(logging.WARNING, logger=manager_logger.name), pytest.raises(InvalidResetPasswordTokenError):
        await manager._account_token_security.get_reset_password_context(token, user_db=user_db)

    assert [getattr(record, "event", None) for record in caplog.records] == ["token_validation_failed"]


def test_password_fingerprint_matches_expected_hmac() -> None:
    """Password fingerprints are deterministic HMAC-SHA256 values over the stored hash."""
    user_db = AsyncMock()
    password_helper = PasswordHelper()
    manager = TrackingUserManager(user_db, password_helper)
    hashed_password = password_helper.hash("test-password")

    fingerprint = manager._account_tokens.password_fingerprint(hashed_password)

    assert fingerprint == manager.tokens.password_fingerprint(hashed_password)
    assert len(fingerprint) == EXPECTED_SHA256_HEX_LENGTH
    int(fingerprint, 16)
