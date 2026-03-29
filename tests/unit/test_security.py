"""Security-oriented tests for constant-time comparisons."""

from __future__ import annotations

import logging
import secrets
from dataclasses import replace
from datetime import UTC, datetime, timedelta
from typing import cast
from unittest.mock import AsyncMock, patch

import jwt
import pytest

from litestar_auth.exceptions import InvalidResetPasswordTokenError, InvalidVerifyTokenError
from litestar_auth.manager import MAX_PASSWORD_LENGTH, RESET_PASSWORD_TOKEN_AUDIENCE, require_password_length
from litestar_auth.manager import logger as manager_logger
from litestar_auth.password import PasswordHelper
from litestar_auth.totp import verify_totp
from tests.unit.test_manager import TrackingUserManager, _build_user

pytestmark = pytest.mark.unit


def _full_claims(**overrides: object) -> dict[str, object]:
    """Build a complete JWT payload with all required claims.

    Returns:
        Payload dictionary including ``exp``, ``iat``, ``nbf``, and ``jti``.
    """
    now = datetime.now(tz=UTC)
    base: dict[str, object] = {
        "iat": now,
        "nbf": now,
        "exp": now + timedelta(hours=1),
        "jti": secrets.token_hex(16),
    }
    base.update(overrides)
    return base


@pytest.mark.parametrize(
    ("audience", "should_pass"),
    [
        pytest.param("litestar-auth:verify", True, id="match"),
        pytest.param("litestar-auth:ver", False, id="prefix-miss"),
        pytest.param("x", False, id="short-miss"),
        pytest.param(
            ["litestar-auth:reset-password", "litestar-auth:verify"],
            True,
            id="audience-list",
        ),
    ],
)
async def test_manager_verify_validates_audience(
    audience: str | list[str],
    *,
    should_pass: bool,
) -> None:
    """Manager token validation enforces the expected JWT audience."""
    user_db = AsyncMock()
    password_helper = PasswordHelper()
    manager = TrackingUserManager(user_db, password_helper)
    user = _build_user(password_helper)
    user_db.get.return_value = user
    user_db.update.return_value = user
    token = jwt.encode(
        _full_claims(sub=str(user.id), aud=audience),
        manager.verification_token_secret.get_secret_value(),
        algorithm="HS256",
    )
    if should_pass:
        result = await manager.verify(token)
        assert result is user
        return

    with pytest.raises(InvalidVerifyTokenError):
        await manager.verify(token)


def test_timing_verify_totp_uses_compare_digest_for_prefix_and_non_prefix_mismatches() -> None:
    """TOTP code comparison delegates to ``compare_digest`` regardless of shared prefixes."""
    calls: list[tuple[str, str]] = []

    def record_compare_digest(left: str, right: str) -> bool:
        calls.append((left, right))
        return left == right

    with (
        patch("litestar_auth.totp._current_counter", return_value=1),
        patch("litestar_auth.totp._generate_totp_code", return_value="123456"),
        patch("litestar_auth.totp.hmac.compare_digest", side_effect=record_compare_digest),
    ):
        assert verify_totp("SECRET", "123450") is False
        assert verify_totp("SECRET", "999999") is False

    assert calls == [("123456", "123450")] * 3 + [("123456", "999999")] * 3


def test_timing_password_helper_verify_delegates_to_pwdlib_verify() -> None:
    """Password verification remains delegated to pwdlib's verifier."""
    helper = PasswordHelper()

    with patch.object(helper.password_hash, "verify", return_value=True) as verify_mock:
        assert helper.verify("plain-password", "hashed-password") is True

    verify_mock.assert_called_once_with("plain-password", "hashed-password")


def test_require_password_length_rejects_passwords_longer_than_default_maximum() -> None:
    """Manager-level password validation rejects oversized passwords before hashing."""
    with pytest.raises(ValueError, match=f"at most {MAX_PASSWORD_LENGTH} characters"):
        require_password_length("a" * (MAX_PASSWORD_LENGTH + 1))


def test_require_password_length_allows_passwords_at_default_maximum() -> None:
    """The default maximum length still accepts passwords up to 128 characters."""
    require_password_length("a" * MAX_PASSWORD_LENGTH)


@pytest.mark.parametrize(
    "payload",
    [
        pytest.param({}, id="missing"),
        pytest.param({"password_fingerprint": 123}, id="non-string"),
    ],
)
async def test_reset_password_rejects_missing_or_invalid_fingerprint_claim(
    caplog: pytest.LogCaptureFixture,
    payload: dict[str, object],
) -> None:
    """Reset tokens must carry a string password fingerprint claim."""
    user_db = AsyncMock()
    password_helper = PasswordHelper()
    manager = TrackingUserManager(user_db, password_helper)
    user = _build_user(password_helper)
    user_db.get.return_value = user

    token = jwt.encode(
        _full_claims(sub=str(user.id), aud=RESET_PASSWORD_TOKEN_AUDIENCE, **payload),
        manager.reset_password_token_secret.get_secret_value(),
        algorithm="HS256",
    )

    with (
        caplog.at_level(logging.WARNING, logger=manager_logger.name),
        pytest.raises(InvalidResetPasswordTokenError),
    ):
        await manager.reset_password(token, "new-password")

    assert "Reset token missing password fingerprint" in caplog.messages
    assert cast("str | None", getattr(caplog.records[-1], "event", None)) == "token_validation_failed"
    user_db.update.assert_not_awaited()


async def test_reset_password_rejects_mismatched_fingerprint(caplog: pytest.LogCaptureFixture) -> None:
    """Reset tokens are rejected once the current password fingerprint no longer matches."""
    user_db = AsyncMock()
    password_helper = PasswordHelper()
    manager = TrackingUserManager(user_db, password_helper)
    user = _build_user(password_helper)
    changed_user = replace(user, hashed_password=password_helper.hash("other-password"))
    user_db.get.return_value = changed_user

    token = jwt.encode(
        _full_claims(
            sub=str(user.id),
            aud=RESET_PASSWORD_TOKEN_AUDIENCE,
            password_fingerprint=manager._password_fingerprint(user.hashed_password),
        ),
        manager.reset_password_token_secret.get_secret_value(),
        algorithm="HS256",
    )

    with (
        caplog.at_level(logging.WARNING, logger=manager_logger.name),
        pytest.raises(InvalidResetPasswordTokenError),
    ):
        await manager.reset_password(token, "new-password")

    assert "Reset token fingerprint mismatch (password changed)" in caplog.messages
    assert cast("str | None", getattr(caplog.records[-1], "event", None)) == "token_validation_failed"
    user_db.update.assert_not_awaited()


async def test_reset_password_accepts_matching_fingerprint() -> None:
    """Valid reset tokens continue to work when the fingerprint matches the current password hash."""
    user_db = AsyncMock()
    password_helper = PasswordHelper()
    manager = TrackingUserManager(user_db, password_helper)
    user = _build_user(password_helper)
    updated_user = replace(user, hashed_password=password_helper.hash("new-password"))
    user_db.get.return_value = user
    user_db.update.return_value = updated_user

    token = jwt.encode(
        _full_claims(
            sub=str(user.id),
            aud=RESET_PASSWORD_TOKEN_AUDIENCE,
            password_fingerprint=manager._password_fingerprint(user.hashed_password),
        ),
        manager.reset_password_token_secret.get_secret_value(),
        algorithm="HS256",
    )

    result = await manager.reset_password(token, "new-password")

    assert result is updated_user
    user_db.update.assert_awaited_once()


def test_dummy_reset_password_token_keeps_password_fingerprint_structure() -> None:
    """Dummy reset tokens retain the same fingerprint claim shape as real reset tokens."""
    user_db = AsyncMock()
    password_helper = PasswordHelper()
    manager = TrackingUserManager(user_db, password_helper)
    dummy_hash = password_helper.hash("dummy-password")

    token = manager._account_tokens.write_reset_password_token(None, dummy_hash=dummy_hash)

    payload = jwt.decode(
        token,
        manager.reset_password_token_secret.get_secret_value(),
        algorithms=["HS256"],
        audience=RESET_PASSWORD_TOKEN_AUDIENCE,
    )

    assert not payload["sub"]
    assert payload["password_fingerprint"] == manager._password_fingerprint(dummy_hash)
