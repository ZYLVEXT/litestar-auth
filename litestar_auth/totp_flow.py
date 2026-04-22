"""TOTP login-flow orchestration for pending-token issue and verification."""

from __future__ import annotations

import logging
import secrets
import warnings
from collections.abc import Awaitable, Callable
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from typing import TYPE_CHECKING, Any, Protocol, TypeGuard, cast

import jwt
from jwt import ExpiredSignatureError, InvalidTokenError

from litestar_auth.config import TOTP_PENDING_AUDIENCE
from litestar_auth.exceptions import ConfigurationError, TokenError
from litestar_auth.totp import SecurityWarning, TotpAlgorithm, UsedTotpCodeStore, verify_totp_with_store
from litestar_auth.types import TotpUserProtocol

if TYPE_CHECKING:
    from litestar_auth.authentication.strategy.jwt import JWTDenylistStore

_DEFAULT_PENDING_TOKEN_LIFETIME = timedelta(minutes=5)
_PENDING_JTI_HEX_LENGTH = 32
logger = logging.getLogger(__name__)
_pending_jti_disabled_logged = False


class InvalidTotpPendingTokenError(Exception):
    """Raised when a pending TOTP token is invalid or expired."""


class InvalidTotpCodeError(Exception):
    """Raised when a TOTP code cannot complete the pending login flow."""


def _warn_pending_jti_disabled() -> None:
    """Emit warning and structured telemetry for unsafe pending-token replay posture."""
    global _pending_jti_disabled_logged  # noqa: PLW0603
    warnings.warn(
        "TOTP pending-token JTI deduplication is DISABLED because unsafe_testing=True.",
        SecurityWarning,
        stacklevel=3,
    )
    if _pending_jti_disabled_logged:
        return
    logger.critical(
        "TOTP pending-token JTI deduplication is disabled because unsafe_testing=True.",
        extra={"event": "totp_pending_jti_dedup_disabled", "unsafe_testing": True},
    )
    _pending_jti_disabled_logged = True


class TotpFlowUserManagerProtocol[UP: TotpUserProtocol[Any], ID](Protocol):
    """User-manager behavior required by TOTP login-flow orchestration."""

    async def get(self, user_id: ID) -> UP | None:
        """Return the user for the given identifier."""

    async def read_totp_secret(self, secret: str | None) -> str | None:
        """Return a plain-text TOTP secret from storage."""


type PendingUserValidator[UP] = Callable[[UP], Awaitable[None]]


@dataclass(frozen=True, slots=True)
class PendingTotpLogin[UP: TotpUserProtocol[Any]]:
    """Decoded pending-login state required to finish a TOTP handshake."""

    user: UP
    pending_jti: str
    expires_at: datetime


class TotpLoginFlowService[UP: TotpUserProtocol[Any], ID]:
    """Issue and verify pending TOTP login challenges."""

    def __init__(  # noqa: PLR0913
        self,
        *,
        user_manager: TotpFlowUserManagerProtocol[UP, ID],
        totp_pending_secret: str,
        totp_pending_lifetime: timedelta = _DEFAULT_PENDING_TOKEN_LIFETIME,
        totp_algorithm: TotpAlgorithm = "SHA256",
        require_replay_protection: bool = True,
        used_tokens_store: UsedTotpCodeStore | None = None,
        pending_jti_store: JWTDenylistStore | None = None,
        id_parser: Callable[[str], ID] | None = None,
        unsafe_testing: bool = False,
    ) -> None:
        """Bind the dependencies used by the pending-login handshake."""
        self._user_manager = user_manager
        self._totp_pending_secret = totp_pending_secret
        self._totp_pending_lifetime = totp_pending_lifetime
        self._totp_algorithm = totp_algorithm
        self._require_replay_protection = require_replay_protection
        self._used_tokens_store = used_tokens_store
        self._pending_jti_store = pending_jti_store
        self._id_parser = id_parser
        self._unsafe_testing = unsafe_testing

    async def issue_pending_token(self, user: UP) -> str | None:
        """Return a pending-login JWT when the user has TOTP enabled."""
        if await self._user_manager.read_totp_secret(user.totp_secret) is None:
            return None
        issued_at = datetime.now(tz=UTC)
        payload = {
            "sub": str(user.id),
            "aud": TOTP_PENDING_AUDIENCE,
            "iat": issued_at,
            "nbf": issued_at,
            "exp": issued_at + self._totp_pending_lifetime,
            "jti": secrets.token_hex(16),
        }
        return jwt.encode(payload, self._totp_pending_secret, algorithm="HS256")

    async def authenticate_pending_login(
        self,
        *,
        pending_token: str,
        code: str,
        validate_user: PendingUserValidator[UP] | None = None,
    ) -> UP:
        """Validate a pending-login token plus TOTP code and return the resolved user.

        Returns:
            The user resolved from the verified pending-login challenge.

        Raises:
            InvalidTotpCodeError: If the TOTP code is invalid or TOTP is not enabled.
        """
        pending_login = await self._resolve_pending_login(pending_token)
        if validate_user is not None:
            await validate_user(pending_login.user)
        secret = await self._user_manager.read_totp_secret(pending_login.user.totp_secret)
        if not secret or not await verify_totp_with_store(
            secret,
            code,
            user_id=pending_login.user.id,
            used_tokens_store=self._used_tokens_store,
            algorithm=self._totp_algorithm,
            require_replay_protection=self._require_replay_protection,
            unsafe_testing=self._unsafe_testing,
        ):
            raise InvalidTotpCodeError
        await self._deny_pending_login(pending_login)
        return pending_login.user

    async def _resolve_pending_login(self, pending_token: str) -> PendingTotpLogin[UP]:
        try:
            payload = jwt.decode(
                pending_token,
                self._totp_pending_secret,
                algorithms=["HS256"],
                audience=TOTP_PENDING_AUDIENCE,
                options={"require": ["exp", "aud", "iat", "nbf", "jti"]},
            )
        except (ExpiredSignatureError, InvalidTokenError) as exc:
            raise InvalidTotpPendingTokenError from exc

        subject = payload.get("sub")
        if not isinstance(subject, str) or not subject:
            raise InvalidTotpPendingTokenError

        pending_jti_value = payload.get("jti")
        if not self._is_structurally_valid_jti(pending_jti_value):
            raise InvalidTotpPendingTokenError
        pending_jti = pending_jti_value

        expires_at = self._parse_pending_expiration(payload.get("exp"))
        if expires_at is None:
            raise InvalidTotpPendingTokenError

        if self._pending_jti_store is not None and await self._pending_jti_store.is_denied(pending_jti):
            raise InvalidTotpPendingTokenError

        user = await self._user_manager.get(self._parse_user_id(subject))
        if user is None:
            raise InvalidTotpPendingTokenError

        return PendingTotpLogin(user=user, pending_jti=pending_jti, expires_at=expires_at)

    async def _deny_pending_login(self, pending_login: PendingTotpLogin[UP]) -> None:
        if self._pending_jti_store is None:
            if not self._unsafe_testing:
                msg = (
                    "TOTP pending-token JTI deduplication is required in production. "
                    "Configure a JWTDenylistStore for pending_jti_store."
                )
                raise ConfigurationError(msg)
            _warn_pending_jti_disabled()
            return

        ttl_seconds = max(int((pending_login.expires_at - datetime.now(tz=UTC)).total_seconds()), 1)
        recorded = await self._pending_jti_store.deny(pending_login.pending_jti, ttl_seconds=ttl_seconds)
        if not recorded:
            msg = (
                "Could not record pending-login JTI in the denylist (in-memory store at capacity). "
                "Use RedisJWTDenylistStore or increase max_entries."
            )
            raise TokenError(msg)

    def _parse_user_id(self, subject: str) -> ID:
        # JWT `sub` is a string; when no id_parser is configured, ID must be str-compatible.
        return self._id_parser(subject) if self._id_parser is not None else cast("ID", subject)

    @staticmethod
    def _parse_pending_expiration(expiration: object) -> datetime | None:
        if isinstance(expiration, datetime):
            return expiration.astimezone(UTC) if expiration.tzinfo is not None else expiration.replace(tzinfo=UTC)
        if isinstance(expiration, int):
            return datetime.fromtimestamp(expiration, tz=UTC)
        return None

    @staticmethod
    def _is_structurally_valid_jti(jti: object) -> TypeGuard[str]:
        if not isinstance(jti, str) or len(jti) != _PENDING_JTI_HEX_LENGTH:
            return False
        try:
            bytes.fromhex(jti)
        except ValueError:
            return False
        return True
