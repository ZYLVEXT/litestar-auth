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
from litestar_auth.totp import (
    SecurityWarning,
    TotpAlgorithm,
    TotpReplayProtection,
    UsedTotpCodeStore,
    _consume_matching_recovery_code,
    verify_totp_with_store,
)
from litestar_auth.types import TotpUserProtocol

if TYPE_CHECKING:
    from litestar import Request

    from litestar_auth.authentication.strategy.jwt import JWTDenylistStore

_DEFAULT_PENDING_TOKEN_LIFETIME = timedelta(minutes=5)
_PENDING_JTI_HEX_LENGTH = 32
_CLIENT_IP_FINGERPRINT_CLAIM = "cip"
_USER_AGENT_FINGERPRINT_CLAIM = "uaf"
logger = logging.getLogger(__name__)


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


@dataclass(slots=True)
class _PendingJtiWarningState:
    """Deduplicate unsafe pending-JTI critical logs for one login-flow service instance."""

    logged: bool = False

    def reset(self) -> None:
        """Allow tests to reset service-local warning deduplication state."""
        self.logged = False


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


@dataclass(frozen=True, slots=True)
class TotpLoginFlowConfig[ID]:
    """Configuration for pending-login TOTP issue and verification."""

    totp_pending_secret: str
    totp_pending_lifetime: timedelta = _DEFAULT_PENDING_TOKEN_LIFETIME
    totp_algorithm: TotpAlgorithm = "SHA256"
    require_replay_protection: bool = True
    used_tokens_store: UsedTotpCodeStore | None = None
    pending_jti_store: JWTDenylistStore | None = None
    id_parser: Callable[[str], ID] | None = None
    require_client_binding: bool = True
    unsafe_testing: bool = False


class TotpLoginFlowService[UP: TotpUserProtocol[Any], ID]:
    """Issue and verify pending TOTP login challenges.

    Pending-login JWTs are single-use through JTI denial and, by default, carry
    hashed client-IP and User-Agent fingerprints. Verification accepts a current
    TOTP code first, then falls back to a one-time recovery code without changing
    the public wrong-code response shape.
    """

    def __init__(
        self,
        *,
        user_manager: TotpFlowUserManagerProtocol[UP, ID],
        config: TotpLoginFlowConfig[ID],
    ) -> None:
        """Bind the dependencies used by the pending-login handshake."""
        self._user_manager = user_manager
        self._totp_pending_secret = config.totp_pending_secret
        self._totp_pending_lifetime = config.totp_pending_lifetime
        self._totp_algorithm = config.totp_algorithm
        self._require_replay_protection = config.require_replay_protection
        self._used_tokens_store = config.used_tokens_store
        self._pending_jti_store = config.pending_jti_store
        self._id_parser = config.id_parser
        self._require_client_binding = config.require_client_binding
        self._unsafe_testing = config.unsafe_testing
        self._password_helper = PasswordHelper.from_defaults()
        self._pending_jti_warning_state = _PendingJtiWarningState()

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
            replay=TotpReplayProtection(
                user_id=pending_login.user.id,
                used_tokens_store=self._used_tokens_store,
                require_replay_protection=self._require_replay_protection,
                unsafe_testing=self._unsafe_testing,
            ),
            algorithm=self._totp_algorithm,
        ) and not await _consume_matching_recovery_code(
            self._user_manager,
            pending_login.user,
            code,
            password_helper=self._password_helper,
        ):
            raise InvalidTotpCodeError
        await self._deny_pending_login(pending_login)
        return pending_login.user

    async def _resolve_pending_login(
        self,
        pending_token: str,
        *,
        client_binding: PendingTotpClientBinding | None = None,
    ) -> PendingTotpLogin[UP]:
        payload = self._decode_pending_token(pending_token)
        subject = self._validate_pending_subject(payload)
        pending_jti = self._validate_pending_jti(payload)
        expires_at = self._validate_pending_expiration(payload)
        await self._ensure_pending_jti_is_unused(pending_jti)
        self._validate_pending_client_binding(payload, client_binding=client_binding)

        user = await self._user_manager.get(self._parse_user_id(subject))
        if user is None:
            raise InvalidTotpPendingTokenError

        return PendingTotpLogin(user=user, pending_jti=pending_jti, expires_at=expires_at)

    def _decode_pending_token(self, pending_token: str) -> dict[str, Any]:
        required_claims = ["exp", "aud", "iat", "nbf", "jti"]
        if self._require_client_binding:
            required_claims.extend([_CLIENT_IP_FINGERPRINT_CLAIM, _USER_AGENT_FINGERPRINT_CLAIM])
        try:
            return jwt.decode(
                pending_token,
                self._totp_pending_secret,
                algorithms=["HS256"],
                audience=TOTP_PENDING_AUDIENCE,
                options={"require": required_claims},
            )
        except (ExpiredSignatureError, InvalidTokenError) as exc:
            raise InvalidTotpPendingTokenError from exc

    @staticmethod
    def _validate_pending_subject(payload: dict[str, Any]) -> str:
        subject = payload.get("sub")
        if not isinstance(subject, str) or not subject:
            raise InvalidTotpPendingTokenError
        return subject

    @classmethod
    def _validate_pending_jti(cls, payload: dict[str, Any]) -> str:
        pending_jti = payload.get("jti")
        if not cls._is_structurally_valid_jti(pending_jti):
            raise InvalidTotpPendingTokenError
        return pending_jti

    @classmethod
    def _validate_pending_expiration(cls, payload: dict[str, Any]) -> datetime:
        expires_at = cls._parse_pending_expiration(payload.get("exp"))
        if expires_at is None:
            raise InvalidTotpPendingTokenError
        return expires_at

    async def _ensure_pending_jti_is_unused(self, pending_jti: str) -> None:
        if self._pending_jti_store is not None and await self._pending_jti_store.is_denied(pending_jti):
            raise InvalidTotpPendingTokenError

    def _validate_pending_client_binding(
        self,
        payload: dict[str, Any],
        *,
        client_binding: PendingTotpClientBinding | None,
    ) -> None:
        if self._require_client_binding and not self._has_valid_client_binding(payload, client_binding):
            raise InvalidTotpPendingTokenError

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
            self._warn_pending_jti_disabled()
            return

        ttl_seconds = max(int((pending_login.expires_at - datetime.now(tz=UTC)).total_seconds()), 1)
        recorded = await self._pending_jti_store.deny(pending_login.pending_jti, ttl_seconds=ttl_seconds)
        if not recorded:
            msg = (
                "Could not record pending-login JTI in the denylist (in-memory store at capacity). "
                "Use RedisJWTDenylistStore or increase max_entries."
            )
            raise TokenError(msg)

    def _warn_pending_jti_disabled(self) -> None:
        """Emit warning and structured telemetry for unsafe pending-token replay posture."""
        warnings.warn(
            "TOTP pending-token JTI deduplication is DISABLED because unsafe_testing=True.",
            SecurityWarning,
            stacklevel=3,
        )
        if self._pending_jti_warning_state.logged:
            return
        logger.critical(
            "TOTP pending-token JTI deduplication is disabled because unsafe_testing=True.",
            extra={"event": "totp_pending_jti_dedup_disabled", "unsafe_testing": True},
        )
        self._pending_jti_warning_state.logged = True

    def _reset_pending_jti_warning_state(self) -> None:
        """Reset this service instance's unsafe pending-JTI warning deduplication state."""
        self._pending_jti_warning_state.reset()

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
