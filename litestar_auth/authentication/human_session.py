"""Typed human cookie-session provider for the neutral authentication core."""

from __future__ import annotations

from collections.abc import Hashable
from typing import TYPE_CHECKING, Any

from authweave_core import (
    Authenticated,
    AuthenticationContext,
    AuthenticationDecision,
    AuthenticationEvidence,
    AuthenticationRuntime,
    CredentialMatch,
    FailureCode,
    Invalid,
    PrincipalRef,
    RequestView,
)

from litestar_auth.authentication.strategy.base import HumanSessionAuthenticated
from litestar_auth.types import UserProtocol

if TYPE_CHECKING:
    from litestar_auth.authentication.strategy.base import HumanSessionStrategy, UserManagerProtocol

_MAX_SESSION_TOKEN_BYTES = 1024


class HumanSessionProvider[UP: UserProtocol[Any], ID: Hashable]:
    """Authenticate one opaque human session carried by a named cookie."""

    def __init__(  # ruff: ignore[too-many-arguments]
        self,
        *,
        name: str,
        cookie_name: str,
        issuer: str,
        profile: str | None = None,
        strategy: HumanSessionStrategy[UP, ID],
        user_manager: UserManagerProtocol[UP, ID],
    ) -> None:
        """Bind request-scoped session dependencies.

        Raises:
            ValueError: If ``cookie_name`` is not a valid ASCII cookie token.
        """
        try:
            encoded_cookie_name = cookie_name.encode("ascii")
        except UnicodeEncodeError as exc:
            msg = "cookie_name must be ASCII"
            raise ValueError(msg) from exc
        if not encoded_cookie_name or any(character in encoded_cookie_name for character in b"=; \t\r\n"):
            msg = "cookie_name must be a non-empty cookie token"
            raise ValueError(msg)
        self.name = name
        self.profile = profile or f"human_session_cookie.{name}"
        self.cookie_name = encoded_cookie_name
        self.issuer = issuer
        self.strategy = strategy
        self.user_manager = user_manager
        self.authenticated_user: UP | None = None

    def load_principal(self, context: AuthenticationContext) -> UP:
        """Return the human model resolved by this request-scoped provider.

        Returns:
            Authenticated human model.

        Raises:
            RuntimeError: If called before this provider authenticated the context.
        """
        if self.authenticated_user is None or context.evidence.provider != self.name:
            msg = "human session principal is unavailable"
            raise RuntimeError(msg)
        return self.authenticated_user

    def match(self, request: RequestView) -> CredentialMatch:
        """Own exactly one matching cookie and reject credential collisions.

        Returns:
            Credential ownership classification for this request.
        """
        cookies = self._presented_tokens(request)
        authorization_present = bool(request.header_values(b"authorization"))
        if authorization_present or len(cookies) > 1:
            return CredentialMatch.AMBIGUOUS
        return CredentialMatch.OWNED if cookies else CredentialMatch.NOT_APPLICABLE

    async def authenticate(
        self,
        request: RequestView,
        runtime: AuthenticationRuntime,  # ruff: ignore[unused-method-argument]
    ) -> AuthenticationDecision:
        """Validate the owned cookie session and create neutral evidence.

        Returns:
            A terminal typed authentication decision.
        """
        tokens = self._presented_tokens(request)
        if len(tokens) != 1:
            return Invalid(FailureCode.AMBIGUOUS_CREDENTIALS)
        raw_token = tokens[0]
        if not raw_token or len(raw_token) > _MAX_SESSION_TOKEN_BYTES:
            return Invalid(FailureCode.MALFORMED)
        try:
            token = raw_token.decode("ascii")
        except UnicodeDecodeError:
            return Invalid(FailureCode.MALFORMED)

        attempt = await self.strategy.authenticate_token(token, self.user_manager)
        if not isinstance(attempt, HumanSessionAuthenticated):
            return attempt
        if getattr(attempt.user, "is_active", True) is not True:
            return Invalid(FailureCode.PRINCIPAL_DISABLED)

        principal = PrincipalRef(issuer=self.issuer, subject=str(attempt.user.id), kind="human")
        evidence = AuthenticationEvidence(
            provider=self.name,
            profile=self.profile,
            method="session_cookie",
            issuer=self.issuer,
            issued_at=attempt.issued_at,
            expires_at=attempt.expires_at,
            credential_id=attempt.credential_id,
        )
        self.authenticated_user = attempt.user
        return Authenticated(AuthenticationContext(subject=principal, actor=principal, evidence=evidence))

    def _presented_tokens(self, request: RequestView) -> tuple[bytes, ...]:
        tokens: list[bytes] = []
        for header in request.header_values(b"cookie"):
            for pair in header.split(b";"):
                name, separator, value = pair.strip().partition(b"=")
                if separator and name == self.cookie_name:
                    tokens.append(value)
        return tuple(tokens)
