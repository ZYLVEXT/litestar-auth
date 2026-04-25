"""TOTP login-flow orchestration for pending-token issue and verification."""

from __future__ import annotations

import logging
import secrets
import warnings
from collections.abc import Awaitable, Callable
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from hashlib import sha256
from hmac import compare_digest
from typing import TYPE_CHECKING, Any, Protocol, TypeGuard, cast

import jwt
from jwt import ExpiredSignatureError, InvalidTokenError

from litestar_auth.config import TOTP_PENDING_AUDIENCE
from litestar_auth.exceptions import ConfigurationError, TokenError
from litestar_auth.password import PasswordHelper
from litestar_auth.ratelimit._helpers import _client_host
from litestar_auth.totp import SecurityWarning, TotpAlgorithm, UsedTotpCodeStore, verify_totp_with_store
from litestar_auth.types import TotpUserProtocol

if TYPE_CHECKING:
    from litestar import Request

    from litestar_auth.authentication.strategy.jwt import JWTDenylistStore

_DEFAULT_PENDING_TOKEN_LIFETIME = timedelta(minutes=5)
_PENDING_JTI_HEX_LENGTH = 32
_CLIENT_IP_FINGERPRINT_CLAIM = "cip"
_USER_AGENT_FINGERPRINT_CLAIM = "uaf"
logger = logging.getLogger(__name__)
_pending_jti_disabled_logged = False


if "InvalidTotpPendingTokenError" not in globals():

    class InvalidTotpPendingTokenError(Exception):  # pragma: no cover - covered on first import before coverage starts.
        """Raised when a pending TOTP token is invalid or expired."""


if "InvalidTotpCodeError" not in globals():

    class InvalidTotpCodeError(Exception):  # pragma: no cover - covered on first import before coverage starts.
        """Raised when a TOTP code cannot complete the pending login flow."""


@dataclass(frozen=True, slots=True)
class PendingTotpClientBinding:
    """Fingerprints binding a pending TOTP token to the issuing client."""

    client_ip_fingerprint: str
    user_agent_fingerprint: str


def _fingerprint_client_binding_value(value: str) -> str:
    """Return the stable SHA-256 hex fingerprint for a client-binding value."""
    return sha256(value.encode()).hexdigest()


def build_pending_totp_client_binding(
    request: Request[Any, Any, Any],
    *,
    trusted_proxy: bool = False,
    trusted_headers: tuple[str, ...] = ("X-Forwarded-For",),
) -> PendingTotpClientBinding:
    """Return hashed client-IP and User-Agent fingerprints for a TOTP pending token."""
    client_ip = _client_host(request, trusted_proxy=trusted_proxy, trusted_headers=trusted_headers)
    user_agent = request.headers.get("User-Agent") or request.headers.get("user-agent") or ""
    return PendingTotpClientBinding(
        client_ip_fingerprint=_fingerprint_client_binding_value(client_ip),
        user_agent_fingerprint=_fingerprint_client_binding_value(user_agent),
    )


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

    async def read_recovery_code_hashes(self, user: UP) -> tuple[str, ...]:
        """Return active TOTP recovery-code hashes for a user."""

    async def consume_recovery_code_hash(self, user: UP, matched_hash: str) -> bool:
        """Atomically consume a matched recovery-code hash."""


type PendingUserValidator[UP] = Callable[[UP], Awaitable[None]]


@dataclass(frozen=True, slots=True)
class PendingTotpLogin[UP: TotpUserProtocol[Any]]:
    """Decoded pending-login state required to finish a TOTP handshake."""

    user: UP
    pending_jti: str
    expires_at: datetime


class TotpLoginFlowService[UP: TotpUserProtocol[Any], ID]:
    """Issue and verify pending TOTP login challenges.

    Pending-login JWTs are single-use through JTI denial and, by default, carry
    hashed client-IP and User-Agent fingerprints. Verification accepts a current
    TOTP code first, then falls back to a one-time recovery code without changing
    the public wrong-code response shape.
    """

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
        require_client_binding: bool = True,
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
        self._require_client_binding = require_client_binding
        self._unsafe_testing = unsafe_testing
        self._password_helper = PasswordHelper.from_defaults()

    async def issue_pending_token(
        self,
        user: UP,
        *,
        client_binding: PendingTotpClientBinding | None = None,
    ) -> str | None:
        """Return a pending-login JWT when the user has TOTP enabled.

        When client binding is required, ``client_binding`` supplies the hashed
        ``cip`` and ``uaf`` claims that `/verify` must match.

        Raises:
            InvalidTotpPendingTokenError: If client binding is required but unavailable.
        """
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
        if self._require_client_binding:
            if client_binding is None:
                raise InvalidTotpPendingTokenError
            payload[_CLIENT_IP_FINGERPRINT_CLAIM] = client_binding.client_ip_fingerprint
            payload[_USER_AGENT_FINGERPRINT_CLAIM] = client_binding.user_agent_fingerprint
        return jwt.encode(payload, self._totp_pending_secret, algorithm="HS256")

    async def authenticate_pending_login(
        self,
        *,
        pending_token: str,
        code: str,
        client_binding: PendingTotpClientBinding | None = None,
        validate_user: PendingUserValidator[UP] | None = None,
    ) -> UP:
        """Validate a pending-login token plus TOTP or recovery code.

        Returns:
            The user resolved from the verified pending-login challenge.

        Raises:
            InvalidTotpCodeError: If the TOTP/recovery code is invalid,
                already consumed, or TOTP is not enabled.

        Invalid pending-token failures propagate as
        ``InvalidTotpPendingTokenError`` from token resolution before any code
        fallback runs.
        """
        pending_login = await self._resolve_pending_login(pending_token, client_binding=client_binding)
        if validate_user is not None:
            await validate_user(pending_login.user)
        secret = await self._user_manager.read_totp_secret(pending_login.user.totp_secret)
        if not secret:
            raise InvalidTotpCodeError
        if not await verify_totp_with_store(
            secret,
            code,
            user_id=pending_login.user.id,
            used_tokens_store=self._used_tokens_store,
            algorithm=self._totp_algorithm,
            require_replay_protection=self._require_replay_protection,
            unsafe_testing=self._unsafe_testing,
        ) and not await self._consume_matching_recovery_code(pending_login.user, code):
            raise InvalidTotpCodeError
        await self._deny_pending_login(pending_login)
        return pending_login.user

    async def _consume_matching_recovery_code(self, user: UP, submitted_code: str) -> bool:
        recovery_code_hashes = await self._user_manager.read_recovery_code_hashes(user)
        matched_hash: str | None = None
        for recovery_code_hash in recovery_code_hashes:
            if self._password_helper.verify(submitted_code, recovery_code_hash):
                matched_hash = recovery_code_hash

        return matched_hash is not None and await self._user_manager.consume_recovery_code_hash(user, matched_hash)

    async def _resolve_pending_login(
        self,
        pending_token: str,
        *,
        client_binding: PendingTotpClientBinding | None = None,
    ) -> PendingTotpLogin[UP]:
        required_claims = ["exp", "aud", "iat", "nbf", "jti"]
        if self._require_client_binding:
            required_claims.extend([_CLIENT_IP_FINGERPRINT_CLAIM, _USER_AGENT_FINGERPRINT_CLAIM])
        try:
            payload = jwt.decode(
                pending_token,
                self._totp_pending_secret,
                algorithms=["HS256"],
                audience=TOTP_PENDING_AUDIENCE,
                options={"require": required_claims},
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

        if self._require_client_binding and not self._has_valid_client_binding(payload, client_binding):
            raise InvalidTotpPendingTokenError

        user = await self._user_manager.get(self._parse_user_id(subject))
        if user is None:
            raise InvalidTotpPendingTokenError

        return PendingTotpLogin(user=user, pending_jti=pending_jti, expires_at=expires_at)

    @staticmethod
    def _has_valid_client_binding(
        payload: dict[str, Any],
        client_binding: PendingTotpClientBinding | None,
    ) -> bool:
        if client_binding is None:
            return False
        expected_client_ip = payload.get(_CLIENT_IP_FINGERPRINT_CLAIM)
        expected_user_agent = payload.get(_USER_AGENT_FINGERPRINT_CLAIM)
        return (
            isinstance(expected_client_ip, str)
            and isinstance(expected_user_agent, str)
            and compare_digest(expected_client_ip, client_binding.client_ip_fingerprint)
            and compare_digest(expected_user_agent, client_binding.user_agent_fingerprint)
        )

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
