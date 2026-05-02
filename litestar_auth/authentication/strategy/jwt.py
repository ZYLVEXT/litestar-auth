"""JWT-backed authentication strategy."""

from __future__ import annotations

import hashlib
import hmac
import logging
import secrets
import time
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from typing import TYPE_CHECKING, NotRequired, Required, TypedDict, Unpack, cast, overload, override

import jwt
from jwt import ExpiredSignatureError, InvalidTokenError

from litestar_auth._jwt_headers import JwtDecodeConfig, decode_signed_jwt, jwt_encode_headers
from litestar_auth.authentication.strategy._jwt_denylist import (
    _INMEMORY_JWT_DENYLIST_STARTUP_WARNING,  # noqa: F401
    _MISSING_JWT_DENYLIST_STORE_ERROR,  # noqa: F401
    InMemoryJWTDenylistStore,  # noqa: F401
    JWTDenylistStore,
    JWTRevocationPosture,
    JWTRevocationPostureKey,  # noqa: F401
    RedisJWTDenylistStore,  # noqa: F401
    _load_redis_asyncio,  # noqa: F401
    _resolve_jwt_revocation,
)
from litestar_auth.authentication.strategy.base import Strategy, UserManagerProtocol
from litestar_auth.config import JWT_ACCESS_TOKEN_AUDIENCE, JWT_TIME_CLAIM_LEEWAY_SECONDS, validate_secret_length
from litestar_auth.exceptions import TokenError
from litestar_auth.types import ID, UP

logger = logging.getLogger(__name__)

if TYPE_CHECKING:
    from collections.abc import Callable

DEFAULT_ALGORITHM = "HS256"
DEFAULT_LIFETIME = timedelta(minutes=15)
_ALLOWED_ALGORITHMS = frozenset(
    {
        "HS256",
        "HS384",
        "HS512",
        "RS256",
        "RS384",
        "RS512",
        "ES256",
        "ES384",
        "ES512",
    },
)


def _default_session_fingerprint(key: bytes) -> Callable[[object], str | None]:
    """Build a fingerprint getter that changes when user security state changes.

    This is best-effort: it returns ``None`` when required attributes are missing.

    Returns:
        Callable that computes a keyed fingerprint for a user-like object.
    """

    def getter(user: object) -> str | None:
        user_id = getattr(user, "id", None)
        email = getattr(user, "email", None)
        hashed_password = getattr(user, "hashed_password", None)
        if user_id is None or not isinstance(email, str) or not isinstance(hashed_password, str):
            return None

        material = f"{user_id}\x1f{email.casefold()}\x1f{hashed_password}".encode()
        return hmac.new(key, material, hashlib.sha256).hexdigest()

    return getter


@dataclass(frozen=True, slots=True)
class JWTStrategyConfig[UP, ID]:
    """Configuration for :class:`JWTStrategy`."""

    secret: str
    verify_key: str | None = None
    algorithm: str = DEFAULT_ALGORITHM
    lifetime: timedelta = DEFAULT_LIFETIME
    subject_decoder: Callable[[str], ID] | None = None
    issuer: str | None = None
    denylist_store: JWTDenylistStore | None = None
    allow_inmemory_denylist: bool = False
    session_fingerprint_getter: Callable[[UP], str | None] | None = None
    session_fingerprint_claim: str = "sfp"


class JWTStrategyOptions[UP, ID](TypedDict):
    """Keyword options accepted by :class:`JWTStrategy`."""

    secret: Required[str]
    verify_key: NotRequired[str | None]
    algorithm: NotRequired[str]
    lifetime: NotRequired[timedelta]
    subject_decoder: NotRequired[Callable[[str], ID] | None]
    issuer: NotRequired[str | None]
    denylist_store: NotRequired[JWTDenylistStore | None]
    allow_inmemory_denylist: NotRequired[bool]
    session_fingerprint_getter: NotRequired[Callable[[UP], str | None] | None]
    session_fingerprint_claim: NotRequired[str]


class JWTStrategy(Strategy[UP, ID]):
    """Stateless strategy that stores user identifiers inside JWTs.

    JWT access tokens issued by this strategy are designed to be short-lived
    and stateless. Revocation uses the configured denylist keyed by the ``jti``
    claim so individual tokens can be explicitly revoked before expiration when
    :meth:`destroy_token` is called.

    Production deployments should pass a shared denylist store such as
    :class:`RedisJWTDenylistStore`. Single-process tests, development apps, and
    consciously single-process deployments can opt into :class:`InMemoryJWTDenylistStore` with
    ``allow_inmemory_denylist=True``. Inspect :attr:`revocation_posture` to
    determine whether a concrete strategy instance uses process-local or durable
    shared-store revocation.
    """

    @overload
    def __init__(self, *, config: JWTStrategyConfig[UP, ID]) -> None: ...  # pragma: no cover

    @overload
    def __init__(self, **options: Unpack[JWTStrategyOptions[UP, ID]]) -> None: ...  # pragma: no cover

    def __init__(
        self,
        *,
        config: JWTStrategyConfig[UP, ID] | None = None,
        **options: Unpack[JWTStrategyOptions[UP, ID]],
    ) -> None:
        """Initialize the JWT strategy.

        Args:
            config: JWT strategy configuration.
            **options: Individual JWT strategy settings. Do not combine with
                ``config``.

        Raises:
            ValueError: If ``config`` and keyword options are combined.
            ValueError: Raised when the configured algorithm is not allow-listed, when
                no denylist store is configured, or when both revocation configuration
                paths are supplied.
        """
        if config is not None and options:
            msg = "Pass either JWTStrategyConfig or keyword options, not both."
            raise ValueError(msg)
        settings = JWTStrategyConfig(**options) if config is None else config
        if settings.algorithm not in _ALLOWED_ALGORITHMS:
            msg = f"Unsupported JWT algorithm '{settings.algorithm}'. Allowed algorithms: {sorted(_ALLOWED_ALGORITHMS)}"
            raise ValueError(msg)

        validate_secret_length(settings.secret, label="JWT signing secret")
        self.secret = settings.secret
        self.verify_key = settings.verify_key if settings.verify_key is not None else settings.secret
        self.algorithm = settings.algorithm
        self.lifetime = settings.lifetime
        self.subject_decoder = settings.subject_decoder
        self.issuer = settings.issuer
        self._denylist_store, self._revocation_posture = _resolve_jwt_revocation(
            settings.denylist_store,
            allow_inmemory_denylist=settings.allow_inmemory_denylist,
        )
        # Security: always derive the fingerprint HMAC key from the signing secret
        # (kept private by the strategy), never from the public verify_key.
        fingerprint_key = self.secret.encode()
        self.session_fingerprint_getter = settings.session_fingerprint_getter or _default_session_fingerprint(
            fingerprint_key,
        )
        self.session_fingerprint_claim = settings.session_fingerprint_claim

    @property
    def revocation_posture(self) -> JWTRevocationPosture:
        """Return the explicit revocation durability contract for this strategy."""
        return self._revocation_posture

    @property
    def revocation_is_durable(self) -> bool:
        """Return whether token revocation is backed by a shared store."""
        return self.revocation_posture.revocation_is_durable

    async def _is_token_denied(self, payload: dict[str, object]) -> bool:
        """Return whether the token's ``jti`` is present on the denylist."""
        jti = payload.get("jti")
        if not isinstance(jti, str):
            return False
        return await self._denylist_store.is_denied(jti)

    def _validate_fingerprint(self, payload: dict[str, object], user: UP) -> bool:
        """Return whether the session fingerprint in ``payload`` matches ``user``.

        When the current fingerprint is unavailable (user model lacks the
        required attributes), tokens that *carry* a fingerprint are rejected —
        a token minted with a fingerprint should not silently bypass validation.
        """
        token_fingerprint = payload.get(self.session_fingerprint_claim)
        current_fingerprint = self.session_fingerprint_getter(user)
        if current_fingerprint is None:
            if token_fingerprint is not None:
                logger.warning(
                    "Token carries session fingerprint but current fingerprint is unavailable "
                    "for user %s; rejecting token",
                    getattr(user, "id", "?"),
                )
                return False
            logger.debug("Session fingerprint unavailable for user %s; skipping check", getattr(user, "id", "?"))
            return True
        return isinstance(token_fingerprint, str) and hmac.compare_digest(
            token_fingerprint,
            current_fingerprint,
        )

    def _decode_verified_access_token(self, token: str) -> dict[str, object] | None:
        """Decode and validate a signed access token, or return ``None`` if invalid.

        Returns:
            Verified JWT claims, or ``None`` when decoding fails.
        """
        try:
            raw = decode_signed_jwt(
                token,
                config=JwtDecodeConfig(
                    key=self.verify_key,
                    algorithms=[self.algorithm],
                    audience=JWT_ACCESS_TOKEN_AUDIENCE,
                    options={"require": ["exp", "aud", "iat", "nbf", "jti"]},
                    issuer=self.issuer,
                    leeway=JWT_TIME_CLAIM_LEEWAY_SECONDS,
                ),
            )
        except (ExpiredSignatureError, InvalidTokenError):
            return None
        return raw

    @override
    async def read_token(  # noqa: PLR0911
        self,
        token: str | None,
        user_manager: UserManagerProtocol[UP, ID],
    ) -> UP | None:
        """Decode a JWT token and load its user.

        Returns:
            The matching user, or ``None`` when the token is invalid.
        """
        if token is None:
            return None

        payload = self._decode_verified_access_token(token)
        if payload is None:
            logger.info("JWT decode failed (expired or invalid signature)")
            return None

        if await self._is_token_denied(payload):
            logger.info("JWT denied (revoked)")
            return None

        subject = payload.get("sub")
        if not isinstance(subject, str) or not subject:
            logger.info("JWT missing or invalid 'sub' claim")
            return None

        try:
            user_id = self.subject_decoder(subject) if self.subject_decoder is not None else subject
        except ValueError:
            # Security: avoid logging the subject itself to prevent user enumeration
            # via authentication-failure log analysis (OWASP / NIST SP 800-63B §5.2.2).
            logger.info("JWT subject could not be decoded")
            return None

        if user_id is None:
            return None

        user = await user_manager.get(cast("ID", user_id))
        if user is None:
            logger.info("JWT subject references non-existent user")
            return None

        if not self._validate_fingerprint(payload, user):
            logger.info("JWT fingerprint mismatch")
            return None

        return user

    @override
    async def write_token(self, user: UP) -> str:
        """Generate a JWT token for the provided user.

        Returns:
            The encoded JWT token string.
        """
        issued_at = datetime.now(tz=UTC)
        payload = {
            "sub": str(user.id),
            "aud": JWT_ACCESS_TOKEN_AUDIENCE,
            "iat": issued_at,
            "nbf": issued_at,
            "exp": issued_at + self.lifetime,
            "jti": secrets.token_hex(16),
        }
        if self.issuer is not None:
            payload["iss"] = self.issuer

        fingerprint = self.session_fingerprint_getter(user)
        if fingerprint is not None:
            payload[self.session_fingerprint_claim] = fingerprint
        return jwt.encode(payload, self.secret, algorithm=self.algorithm, headers=jwt_encode_headers())

    @override
    async def destroy_token(self, token: str, user: UP) -> None:
        """Revoke the given token by adding its ``jti`` to the configured denylist.

        Tokens without a ``jti`` claim, or tokens that fail to decode, are ignored.

        Raises:
            TokenError: When the denylist refuses a new revocation (for example, the
                compatibility in-memory store is at ``max_entries`` with no reclaimable slots).
        """
        del user

        try:
            payload = decode_signed_jwt(
                token,
                config=JwtDecodeConfig(
                    key=self.verify_key,
                    algorithms=[self.algorithm],
                    audience=JWT_ACCESS_TOKEN_AUDIENCE,
                    options={
                        "verify_exp": False,
                        "verify_iss": False,
                    },
                ),
            )
        except InvalidTokenError:
            return

        jti = payload.get("jti")
        exp = payload.get("exp")
        if not isinstance(jti, str):
            return
        ttl_seconds = 1
        if isinstance(exp, int):
            ttl_seconds = max(exp - int(time.time()), 1)
        recorded = await self._denylist_store.deny(jti, ttl_seconds=ttl_seconds)
        if not recorded:
            msg = (
                "Could not record JWT revocation in the denylist (in-memory store at capacity). "
                "Use RedisJWTDenylistStore or increase max_entries."
            )
            raise TokenError(msg)
