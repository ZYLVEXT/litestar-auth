"""Tests for the typed human cookie-session provider."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from typing import Any, cast
from uuid import uuid4

import pytest
from authweave_core import (
    Authenticated,
    AuthenticationRuntime,
    CredentialMatch,
    FailureCode,
    Invalid,
    RequestView,
    Unavailable,
)

from litestar_auth.authentication.human_session import HumanSessionProvider
from litestar_auth.authentication.strategy.base import HumanSessionAuthenticated, UserManagerProtocol
from tests._helpers import ExampleUser

pytestmark = pytest.mark.unit


class _Manager:
    """Unused manager double required by the strategy contract."""

    async def get(self, user_id: object) -> ExampleUser | None:
        """Return no user."""
        return None


class _Strategy:
    """Return or raise one configured typed attempt."""

    def __init__(
        self,
        attempt: HumanSessionAuthenticated[ExampleUser] | Invalid | Unavailable | Exception,
    ) -> None:
        """Store the configured attempt."""
        self.attempt = attempt
        self.tokens: list[str] = []

    async def authenticate_token(
        self,
        token: str,
        user_manager: UserManagerProtocol[ExampleUser, object],
    ) -> HumanSessionAuthenticated[ExampleUser] | Invalid | Unavailable:
        """Return the configured attempt.

        Returns:
            Configured attempt object.
        """
        self.tokens.append(token)
        if isinstance(self.attempt, Exception):
            raise self.attempt
        return self.attempt


def _provider(
    attempt: HumanSessionAuthenticated[ExampleUser] | Invalid | Unavailable | Exception,
) -> HumanSessionProvider[ExampleUser, object]:
    """Build a provider around one strategy attempt.

    Returns:
        Request-scoped provider under test.
    """
    return HumanSessionProvider[ExampleUser, object](
        name="human_session",
        cookie_name="session",
        issuer="https://accounts.example.test",
        strategy=_Strategy(attempt),
        user_manager=_Manager(),
    )


def _request(*headers: tuple[bytes, bytes]) -> RequestView:
    """Build a neutral request projection.

    Returns:
        Request view with the supplied headers.
    """
    return RequestView(method="GET", headers=headers)


@pytest.mark.parametrize("cookie_name", ["", "séssion", "bad name", "bad=name", "bad;name"])
def test_provider_rejects_invalid_cookie_names(cookie_name: str) -> None:
    """Cookie lookup must use a bounded ASCII token."""
    with pytest.raises(ValueError, match="cookie"):
        HumanSessionProvider[ExampleUser, object](
            name="human_session",
            cookie_name=cookie_name,
            issuer="https://accounts.example.test",
            strategy=_Strategy(Invalid(FailureCode.INVALID)),
            user_manager=_Manager(),
        )


def test_match_classifies_absent_single_and_colliding_presentations() -> None:
    """Matcher owns one cookie and rejects duplicate or bearer collisions."""
    provider = _provider(Invalid(FailureCode.INVALID))

    assert provider.match(_request()) is CredentialMatch.NOT_APPLICABLE
    assert provider.match(_request((b"cookie", b"other=x; session=token"))) is CredentialMatch.OWNED
    assert (
        provider.match(_request((b"cookie", b"session=one"), (b"cookie", b"session=two"))) is CredentialMatch.AMBIGUOUS
    )
    assert provider.match(_request((b"authorization", b"Bearer token"))) is CredentialMatch.AMBIGUOUS


@pytest.mark.parametrize(
    ("headers", "expected_code"),
    [
        ((), FailureCode.AMBIGUOUS_CREDENTIALS),
        (((b"cookie", b"session="),), FailureCode.MALFORMED),
        (((b"cookie", b"session=\xff"),), FailureCode.MALFORMED),
        (((b"cookie", b"session=" + b"x" * 1025),), FailureCode.MALFORMED),
    ],
)
async def test_authenticate_rejects_malformed_presentations(
    headers: tuple[tuple[bytes, bytes], ...],
    expected_code: FailureCode,
) -> None:
    """Malformed owned cookies produce typed terminal failures."""
    result = await _provider(Invalid(FailureCode.INVALID)).authenticate(
        _request(*headers),
        AuthenticationRuntime(),
    )

    assert result == Invalid(expected_code)


async def test_authenticate_preserves_typed_strategy_failure() -> None:
    """Strategy failures are returned without heuristic reinterpretation."""
    result = await _provider(Invalid(FailureCode.REVOKED)).authenticate(
        _request((b"cookie", b"session=token")),
        AuthenticationRuntime(),
    )

    assert result == Invalid(FailureCode.REVOKED)


async def test_authenticate_does_not_mask_programming_errors_as_storage_outages() -> None:
    """Strategies must return typed outages; unexpected exceptions remain visible."""
    with pytest.raises(RuntimeError, match="storage offline"):
        await _provider(RuntimeError("storage offline")).authenticate(
            _request((b"cookie", b"session=token")),
            AuthenticationRuntime(),
        )


@pytest.mark.parametrize("is_active", [False, 0, None])
async def test_authenticate_rejects_inactive_human(is_active: object) -> None:
    """Inactive human accounts never produce authenticated contexts."""
    user = ExampleUser(id=uuid4(), is_active=cast("Any", is_active))
    result = await _provider(HumanSessionAuthenticated(user)).authenticate(
        _request((b"cookie", b"session=token")),
        AuthenticationRuntime(),
    )

    assert result == Invalid(FailureCode.PRINCIPAL_DISABLED)


async def test_authenticate_publishes_human_principal_and_safe_evidence() -> None:
    """Successful server-side lookup produces neutral evidence and retains the request user."""
    user = ExampleUser(id=uuid4())
    issued_at = datetime.now(tz=UTC)
    expires_at = issued_at + timedelta(hours=1)
    provider = _provider(
        HumanSessionAuthenticated(
            user,
            issued_at=issued_at,
            expires_at=expires_at,
            credential_id="session-id",
        ),
    )

    result = await provider.authenticate(
        _request((b"cookie", b"other=x; session=opaque-token; theme=dark")),
        AuthenticationRuntime(),
    )

    assert isinstance(result, Authenticated)
    assert result.context.subject == result.context.actor
    assert result.context.subject.kind == "human"
    assert result.context.subject.subject == str(user.id)
    assert result.context.evidence.provider == "human_session"
    assert result.context.evidence.profile == "human_session_cookie.human_session"
    assert result.context.evidence.method == "session_cookie"
    assert result.context.evidence.issued_at == issued_at
    assert result.context.evidence.expires_at == expires_at
    assert result.context.evidence.credential_id == "session-id"
    assert provider.authenticated_user is user
    assert provider.load_principal(result.context) is user
    assert "opaque-token" not in repr(result)
