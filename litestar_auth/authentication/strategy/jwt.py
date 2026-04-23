"""JWT-backed authentication strategy."""

from __future__ import annotations

import hashlib
import hmac
import logging
import secrets
import time
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from functools import partial
from typing import TYPE_CHECKING, Literal, Protocol, Self, cast, override

import jwt
from jwt import ExpiredSignatureError, InvalidTokenError

from litestar_auth._optional_deps import _require_redis_asyncio
from litestar_auth.authentication.strategy.base import Strategy, UserManagerProtocol
from litestar_auth.config import JWT_ACCESS_TOKEN_AUDIENCE, JWT_TIME_CLAIM_LEEWAY_SECONDS, validate_secret_length
from litestar_auth.exceptions import TokenError
from litestar_auth.types import ID, UP

logger = logging.getLogger(__name__)

_load_redis_asyncio = partial(_require_redis_asyncio, feature_name="RedisJWTDenylistStore")

if TYPE_CHECKING:
    from collections.abc import Callable

    from litestar_auth._redis_protocols import RedisExpiringValueStoreClient

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
_MISSING_JWT_DENYLIST_STORE_ERROR = (
    "JWTStrategy requires explicit JWT revocation storage. "
    "Configure denylist_store=RedisJWTDenylistStore(...) or another shared JWTDenylistStore for production. "
    "For single-process tests, development, or consciously single-process apps only, set "
    "allow_inmemory_denylist=True to construct InMemoryJWTDenylistStore explicitly."
)
_INMEMORY_JWT_DENYLIST_STARTUP_WARNING = (
    "JWTStrategy is configured with an explicit process-local in-memory denylist. "
    "Revoked tokens are not visible across workers; use RedisJWTDenylistStore or another shared "
    "JWTDenylistStore for production deployments that rely on revocation."
)

type JWTRevocationPostureKey = Literal["in_memory", "shared_store"]


class JWTDenylistStore(Protocol):
    """Shared denylist storage for JWT `jti` revocation."""

    async def deny(self, jti: str, *, ttl_seconds: int) -> bool:
        """Mark a JTI as revoked for ``ttl_seconds``.

        Returns:
            ``True`` when the revocation was recorded or an existing JTI's TTL was refreshed.
            ``False`` when a **new** revocation could not be stored (for example, an
            in-memory store at capacity after pruning expired entries). Implementations
            that always persist (such as Redis) should return ``True``.
        """

    async def is_denied(self, jti: str) -> bool:
        """Return whether the JTI is revoked."""


class InMemoryJWTDenylistStore:
    """Process-local denylist store (best-effort).

    **Capacity:** Each :meth:`deny` call prunes expired JTIs first. When the map is already at
    ``max_entries`` and no expired entries remain, :meth:`deny` **fails closed**: it logs an
    error and does **not** insert the new JTI, preserving every existing active revocation.
    The store never evicts a still-valid revoked JTI to admit another (older releases dropped
    the soonest-expiring entry under pressure, which could revive a revoked token). Size
    ``max_entries`` for peak concurrent revocations or use :class:`RedisJWTDenylistStore` for
    shared, unbounded-by-process-memory semantics in production.
    """

    def __init__(self, *, max_entries: int = 10_000) -> None:
        """Initialize an empty denylist map with per-entry expiration.

        Raises:
            ValueError: If ``max_entries`` is less than 1.
        """
        if max_entries < 1:
            msg = "max_entries must be at least 1"
            raise ValueError(msg)

        self.max_entries = max_entries
        self._denylisted_until: dict[str, float] = {}

    async def deny(self, jti: str, *, ttl_seconds: int) -> bool:
        """Record the revoked JTI (TTL is best-effort in memory).

        When the store is at capacity and no expired rows can be reclaimed, the new revocation
        is skipped (fail-closed) so existing denylist entries are never dropped to make room.

        Returns:
            ``False`` when a new JTI could not be inserted at capacity; ``True`` otherwise.
        """
        now = time.time()
        self._prune_expired(now)
        expires_at = now + max(ttl_seconds, 1)
        if jti in self._denylisted_until:
            self._denylisted_until[jti] = expires_at
            return True
        if len(self._denylisted_until) >= self.max_entries:
            logger.error(
                "Rejected in-memory JWT denylist insert: capacity %d reached with no "
                "expired entries to reclaim (fail closed). Use RedisJWTDenylistStore or "
                "increase max_entries for high-volume deployments.",
                self.max_entries,
            )
            return False

        self._denylisted_until[jti] = expires_at
        return True

    async def is_denied(self, jti: str) -> bool:
        """Return whether the JTI has been revoked in this process."""
        expires_at = self._denylisted_until.get(jti)
        if expires_at is None:
            return False
        if expires_at <= time.time():
            self._denylisted_until.pop(jti, None)
            return False
        return True

    def _prune_expired(self, now: float) -> None:
        """Remove all entries whose TTL has elapsed."""
        expired_jtis = [jti for jti, expires_at in self._denylisted_until.items() if expires_at <= now]
        for expired_jti in expired_jtis:
            self._denylisted_until.pop(expired_jti, None)


class RedisJWTDenylistStore:
    """Redis-backed denylist store keyed by `jti` with TTL."""

    def __init__(
        self,
        *,
        redis: RedisExpiringValueStoreClient,
        key_prefix: str = "litestar_auth:jwt:denylist:",
    ) -> None:
        """Initialize the store with a Redis client and key prefix.

        Args:
            redis: Async Redis client supporting ``get(name)`` plus
                ``setex(name, ttl_seconds, value)``. The same client may also
                be annotated as
                :class:`litestar_auth.contrib.redis.RedisAuthClientProtocol`
                when it backs the contrib preset or TOTP replay store.
            key_prefix: Prefix used to namespace denylist keys by JTI.
        """
        _load_redis_asyncio()
        self.redis = redis
        self.key_prefix = key_prefix

    def _key(self, jti: str) -> str:
        return f"{self.key_prefix}{jti}"

    async def deny(self, jti: str, *, ttl_seconds: int) -> bool:
        """Store the JTI key with an expiry aligned to token lifetime.

        Returns:
            ``True`` after the key is written (Redis denylist writes always succeed).
        """
        await self.redis.setex(self._key(jti), max(ttl_seconds, 1), "1")
        return True

    async def is_denied(self, jti: str) -> bool:
        """Return whether the JTI key exists in Redis."""
        return await self.redis.get(self._key(jti)) is not None


@dataclass(slots=True, frozen=True)
class JWTRevocationPosture:
    """Explicit contract describing the durability semantics of JWT revocation."""

    key: JWTRevocationPostureKey
    denylist_store_type: str
    revocation_is_durable: bool
    requires_explicit_production_opt_in: bool

    @classmethod
    def in_memory(cls, *, denylist_store_type: str) -> Self:
        """Return the explicit process-local in-memory revocation posture."""
        return cls(
            key="in_memory",
            denylist_store_type=denylist_store_type,
            revocation_is_durable=False,
            requires_explicit_production_opt_in=False,
        )

    @classmethod
    def shared_store(cls, *, denylist_store_type: str) -> Self:
        """Return the durable shared-store revocation posture."""
        return cls(
            key="shared_store",
            denylist_store_type=denylist_store_type,
            revocation_is_durable=True,
            requires_explicit_production_opt_in=False,
        )

    @classmethod
    def from_denylist_store(cls, denylist_store: JWTDenylistStore) -> Self:
        """Build the posture contract for a concrete denylist backend.

        Returns:
            The explicit revocation posture for ``denylist_store``.
        """
        store_type = type(denylist_store).__name__
        if isinstance(denylist_store, InMemoryJWTDenylistStore):
            return cls.in_memory(denylist_store_type=store_type)
        return cls.shared_store(denylist_store_type=store_type)

    @property
    def production_validation_error(self) -> str | None:
        """Return the plugin validation error for this posture, if any.

        JWT revocation storage is validated at strategy construction time, so
        constructed postures do not require a second plugin-level compatibility
        override.
        """
        return None

    @property
    def startup_warning(self) -> str | None:
        """Return the startup warning for this posture, if any."""
        if self.revocation_is_durable:
            return None
        return _INMEMORY_JWT_DENYLIST_STARTUP_WARNING


def _resolve_jwt_revocation(
    denylist_store: JWTDenylistStore | None,
    *,
    allow_inmemory_denylist: bool,
) -> tuple[JWTDenylistStore, JWTRevocationPosture]:
    """Resolve the effective denylist backend and its explicit posture contract.

    Returns:
        Tuple of the denylist backend used at runtime and the posture it reports.

    Raises:
        ValueError: If no denylist store is configured or both configuration paths are supplied.
    """
    if denylist_store is not None:
        if allow_inmemory_denylist:
            msg = "allow_inmemory_denylist=True cannot be combined with denylist_store."
            raise ValueError(msg)
        return denylist_store, JWTRevocationPosture.from_denylist_store(denylist_store)

    if not allow_inmemory_denylist:
        raise ValueError(_MISSING_JWT_DENYLIST_STORE_ERROR)

    resolved_denylist_store = InMemoryJWTDenylistStore()
    return resolved_denylist_store, JWTRevocationPosture.from_denylist_store(resolved_denylist_store)


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

    def __init__(  # noqa: PLR0913
        self,
        *,
        secret: str,
        verify_key: str | None = None,
        algorithm: str = DEFAULT_ALGORITHM,
        lifetime: timedelta = DEFAULT_LIFETIME,
        subject_decoder: Callable[[str], ID] | None = None,
        issuer: str | None = None,
        denylist_store: JWTDenylistStore | None = None,
        allow_inmemory_denylist: bool = False,
        session_fingerprint_getter: Callable[[UP], str | None] | None = None,
        session_fingerprint_claim: str = "sfp",
    ) -> None:
        """Initialize the JWT strategy.

        Args:
            secret: Signing secret or private key used for JWT encoding.
            verify_key: Optional verification key used for JWT decoding. When
                omitted, ``secret`` is used for both encoding and decoding.
            algorithm: JWT signing algorithm.
            lifetime: Token lifetime added to the expiration claim.
            subject_decoder: Optional callable that converts the ``sub`` claim
                into the identifier type expected by the user manager.
            issuer: Optional issuer string to embed in the ``iss`` claim and
                validate when decoding.
            denylist_store: Shared denylist backend for token revocation across
                workers. Omit only when using ``allow_inmemory_denylist=True``.
            allow_inmemory_denylist: Explicitly construct a process-local
                :class:`InMemoryJWTDenylistStore` for single-process tests or
                development. Do not combine with ``denylist_store``.
            session_fingerprint_getter: Optional callable that returns a fingerprint
                representing a user's current security state. When the returned value
                is embedded into tokens, password/email changes can invalidate old
                tokens without server-side session storage.
            session_fingerprint_claim: JWT claim name used to store the session
                fingerprint.

        Raises:
            ValueError: Raised when the configured algorithm is not allow-listed, when
                no denylist store is configured, or when both revocation configuration
                paths are supplied.
        """
        if algorithm not in _ALLOWED_ALGORITHMS:
            msg = f"Unsupported JWT algorithm '{algorithm}'. Allowed algorithms: {sorted(_ALLOWED_ALGORITHMS)}"
            raise ValueError(msg)

        validate_secret_length(secret, label="JWT signing secret")
        self.secret = secret
        self.verify_key = verify_key if verify_key is not None else secret
        self.algorithm = algorithm
        self.lifetime = lifetime
        self.subject_decoder = subject_decoder
        self.issuer = issuer
        self._denylist_store, self._revocation_posture = _resolve_jwt_revocation(
            denylist_store,
            allow_inmemory_denylist=allow_inmemory_denylist,
        )
        # Security: always derive the fingerprint HMAC key from the signing secret
        # (kept private by the strategy), never from the public verify_key.
        fingerprint_key = self.secret.encode()
        self.session_fingerprint_getter = session_fingerprint_getter or _default_session_fingerprint(fingerprint_key)
        self.session_fingerprint_claim = session_fingerprint_claim

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
            if self.issuer is None:
                raw = jwt.decode(
                    token,
                    self.verify_key,
                    algorithms=[self.algorithm],
                    audience=JWT_ACCESS_TOKEN_AUDIENCE,
                    leeway=JWT_TIME_CLAIM_LEEWAY_SECONDS,
                    options={"require": ["exp", "aud", "iat", "nbf", "jti"]},
                )
            else:
                raw = jwt.decode(
                    token,
                    self.verify_key,
                    algorithms=[self.algorithm],
                    audience=JWT_ACCESS_TOKEN_AUDIENCE,
                    issuer=self.issuer,
                    leeway=JWT_TIME_CLAIM_LEEWAY_SECONDS,
                    options={"require": ["exp", "aud", "iat", "nbf", "jti"]},
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
        return jwt.encode(payload, self.secret, algorithm=self.algorithm)

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
            payload = jwt.decode(
                token,
                self.verify_key,
                algorithms=[self.algorithm],
                audience=JWT_ACCESS_TOKEN_AUDIENCE,
                options={
                    "verify_exp": False,
                    "verify_iss": False,
                },
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
