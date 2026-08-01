"""Redis-backed authentication strategy."""

from __future__ import annotations

import json
from contextvars import ContextVar
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from functools import partial
from importlib import import_module
from math import ceil
from typing import TYPE_CHECKING, NotRequired, Protocol, Required, TypedDict, Unpack, cast, overload, override
from uuid import uuid4

from authweave_core import FailureCode, Invalid, Unavailable

from litestar_auth._optional_deps import _require_redis_asyncio
from litestar_auth._redis_protocols import (
    RedisConditionalSetClient,
    RedisDeleteClient,
    RedisKeyExpiryClient,
    RedisScriptEvalClient,
    RedisSetMembershipClient,
    RedisStoredValue,
    RedisValueReadClient,
)
from litestar_auth.authentication.strategy._db_metadata import _RefreshTokenMetadataMixin
from litestar_auth.authentication.strategy._opaque_tokens import (
    build_opaque_token_key,
    mint_opaque_token,
    validate_token_bytes,
)
from litestar_auth.authentication.strategy.base import (
    HumanSessionAuthenticated,
    RefreshSession,
    Strategy,
    UserManagerProtocol,
)
from litestar_auth.config import validate_production_secret
from litestar_auth.exceptions import ConfigurationError
from litestar_auth.ratelimit._key_derivation import _safe_key_part
from litestar_auth.types import ID, UP

if TYPE_CHECKING:
    from collections.abc import Callable

DEFAULT_KEY_PREFIX = "litestar_auth:token:"
DEFAULT_LIFETIME = timedelta(hours=1)
DEFAULT_REFRESH_LIFETIME = timedelta(days=30)
DEFAULT_TOKEN_BYTES = 32
_TOTP_STEPUP_SEGMENT = "totp_stepup"
_PAYLOAD_FORMAT_VERSION = "v1"
_REFRESH_PAYLOAD_FORMAT_VERSION = 1

_REDIS_ROTATE_REFRESH_TOKEN_SCRIPT = """
local current = redis.call("GET", KEYS[1])
if not current or current ~= ARGV[1] then
    local compromised_session = redis.call("GET", KEYS[3])
    if compromised_session then
        local active_refresh = redis.call("GET", KEYS[4])
        if active_refresh then redis.call("DEL", active_refresh) end
        redis.call("DEL", KEYS[4])
        local access_keys = redis.call("SMEMBERS", KEYS[5])
        if #access_keys > 0 then redis.call("DEL", unpack(access_keys)) end
        redis.call("DEL", KEYS[5])
    end
    return 0
end
redis.call("DEL", KEYS[1])
redis.call("SET", KEYS[2], ARGV[2], "EX", ARGV[3])
redis.call("SET", KEYS[3], ARGV[4], "EX", ARGV[3])
redis.call("SET", KEYS[4], KEYS[2], "EX", ARGV[3])
local access_keys = redis.call("SMEMBERS", KEYS[5])
if #access_keys > 0 then redis.call("DEL", unpack(access_keys)) end
redis.call("DEL", KEYS[5])
return 1
"""

_REDIS_WRITE_SESSION_ACCESS_TOKEN_SCRIPT = """
if redis.call("GET", KEYS[1]) ~= KEYS[2] or redis.call("GET", KEYS[2]) ~= ARGV[1] then return 0 end
redis.call("SET", KEYS[3], ARGV[2], "EX", ARGV[3])
redis.call("SADD", KEYS[4], KEYS[3])
redis.call("EXPIRE", KEYS[4], ARGV[3])
return 1
"""

_REDIS_REVOKE_REFRESH_SESSION_SCRIPT = """
local active_refresh = redis.call("GET", KEYS[1])
if not active_refresh then return 0 end
redis.call("DEL", active_refresh)
redis.call("DEL", KEYS[1])
local access_keys = redis.call("SMEMBERS", KEYS[2])
if #access_keys > 0 then redis.call("DEL", unpack(access_keys)) end
redis.call("DEL", KEYS[2])
redis.call("SREM", KEYS[3], KEYS[1])
return 1
"""

_REDIS_INVALIDATE_USER_TOKENS_SCRIPT = """
redis.call("INCR", KEYS[1])

local token_keys = redis.call("SMEMBERS", KEYS[2])
if #token_keys > 0 then
    redis.call("DEL", unpack(token_keys))
end
redis.call("DEL", KEYS[2])

local stepup_keys = redis.call("SMEMBERS", KEYS[3])
if #stepup_keys > 0 then
    redis.call("DEL", unpack(stepup_keys))
end
redis.call("DEL", KEYS[3])

local session_keys = redis.call("SMEMBERS", KEYS[4])
for _, session_key in ipairs(session_keys) do
    local refresh_key = redis.call("GET", session_key)
    if refresh_key then redis.call("DEL", refresh_key) end
    redis.call("DEL", session_key)
    local session_part = string.sub(session_key, string.len(ARGV[1] .. "refresh_session:") + 1)
    local access_index = ARGV[1] .. "session_access:" .. session_part
    local access_keys = redis.call("SMEMBERS", access_index)
    if #access_keys > 0 then redis.call("DEL", unpack(access_keys)) end
    redis.call("DEL", access_index)
end
redis.call("DEL", KEYS[4])

return 1
"""

_load_redis_asyncio = partial(_require_redis_asyncio, feature_name="RedisTokenStrategy")


class RedisClientProtocol(
    RedisValueReadClient,
    RedisConditionalSetClient,
    RedisDeleteClient,
    RedisSetMembershipClient,
    RedisKeyExpiryClient,
    RedisScriptEvalClient,
    Protocol,
):
    """Minimal async Redis client interface used by the token strategy."""


@dataclass(frozen=True, slots=True)
class RedisTokenStrategyConfig[ID]:
    """Configuration for :class:`RedisTokenStrategy`."""

    redis: RedisClientProtocol
    token_hash_secret: str
    lifetime: timedelta = DEFAULT_LIFETIME
    refresh_lifetime: timedelta = DEFAULT_REFRESH_LIFETIME
    token_bytes: int = DEFAULT_TOKEN_BYTES
    key_prefix: str = DEFAULT_KEY_PREFIX
    subject_decoder: Callable[[str], ID] | None = None


class RedisTokenStrategyOptions[ID](TypedDict):
    """Keyword options accepted by :class:`RedisTokenStrategy`."""

    redis: Required[RedisClientProtocol]
    token_hash_secret: Required[str]
    lifetime: NotRequired[timedelta]
    refresh_lifetime: NotRequired[timedelta]
    token_bytes: NotRequired[int]
    key_prefix: NotRequired[str]
    subject_decoder: NotRequired[Callable[[str], ID] | None]


class RedisTokenStrategy(_RefreshTokenMetadataMixin, Strategy[UP, ID]):
    """Stateful strategy that stores opaque tokens in Redis with TTL."""

    @overload
    def __init__(self, *, config: RedisTokenStrategyConfig[ID]) -> None: ...

    @overload
    def __init__(self, **options: Unpack[RedisTokenStrategyOptions[ID]]) -> None: ...

    def __init__(
        self,
        *,
        config: RedisTokenStrategyConfig[ID] | None = None,
        **options: Unpack[RedisTokenStrategyOptions[ID]],
    ) -> None:
        """Initialize the strategy.

        Args:
            config: Redis strategy configuration.
            **options: Individual Redis strategy settings. Do not combine with
                ``config``.

        Raises:
            ValueError: If ``config`` and keyword options are combined.
            ConfigurationError: When ``token_hash_secret`` fails minimum-length requirements.
        """
        if config is not None and options:
            msg = "Pass either RedisTokenStrategyConfig or keyword options, not both."
            raise ValueError(msg)
        settings = RedisTokenStrategyConfig(**options) if config is None else config
        _load_redis_asyncio()
        self._redis_error = cast("type[Exception]", import_module("redis.exceptions").RedisError)
        try:
            validate_production_secret(settings.token_hash_secret, label="RedisTokenStrategy token_hash_secret")
        except ConfigurationError as exc:
            raise ConfigurationError(str(exc)) from exc
        validate_token_bytes(settings.token_bytes, label="RedisTokenStrategy")

        self.redis = settings.redis
        self._token_hash_secret = settings.token_hash_secret.encode()
        self.lifetime = settings.lifetime
        self.refresh_lifetime = settings.refresh_lifetime
        self.token_bytes = settings.token_bytes
        self.key_prefix = settings.key_prefix
        self.subject_decoder = settings.subject_decoder
        self._refresh_token_request_metadata: ContextVar[dict[str, str] | None] = ContextVar(
            "redis_refresh_token_request_metadata",
            default=None,
        )

    def _key(self, token: str) -> str:
        """Return the Redis key for a token."""
        return build_opaque_token_key(
            key_prefix=self.key_prefix,
            token_hash_secret=self._token_hash_secret,
            token=token,
        )

    def _mint_token_key(self) -> tuple[str, str]:
        """Return a raw token and its Redis storage key."""
        token, token_digest = mint_opaque_token(
            token_bytes=self.token_bytes,
            token_hash_secret=self._token_hash_secret,
        )
        return token, f"{self.key_prefix}{token_digest}"

    def _user_index_key(self, user_id: str) -> str:
        """Return the Redis key for the per-user token index."""
        return f"{self.key_prefix}user:{_safe_key_part(user_id)}"

    def _user_epoch_key(self, user_id: str) -> str:
        """Return the Redis key for the per-user invalidation epoch."""
        return f"{self.key_prefix}user_epoch:{_safe_key_part(user_id)}"

    def _refresh_key(self, token: str) -> str:
        """Return the Redis key for a refresh token."""
        return f"{self.key_prefix}refresh:{self._key(token).removeprefix(self.key_prefix)}"

    def _mint_refresh_token_key(self) -> tuple[str, str]:
        """Return a raw refresh token and its storage key."""
        token, token_digest = mint_opaque_token(
            token_bytes=self.token_bytes,
            token_hash_secret=self._token_hash_secret,
        )
        return token, f"{self.key_prefix}refresh:{token_digest}"

    def _refresh_user_index_key(self, user_id: str) -> str:
        """Return the per-user refresh-session index key."""
        return f"{self.key_prefix}refresh_user:{_safe_key_part(user_id)}"

    def _refresh_session_key(self, session_id: str) -> str:
        """Return the public session-id mapping key."""
        return f"{self.key_prefix}refresh_session:{_safe_key_part(session_id)}"

    def _refresh_consumed_key(self, token: str) -> str:
        """Return the replay marker key for a consumed refresh token."""
        return f"{self.key_prefix}refresh_consumed:{self._key(token).removeprefix(self.key_prefix)}"

    def _session_access_index_key(self, session_id: str) -> str:
        """Return the access-token index for one refresh session."""
        return f"{self.key_prefix}session_access:{_safe_key_part(session_id)}"

    def _totp_stepup_key(self, user_id: str, session_id: str) -> str:
        """Return the Redis key for a TOTP step-up marker."""
        return f"{self.key_prefix}{_TOTP_STEPUP_SEGMENT}:{_safe_key_part(user_id)}:{_safe_key_part(session_id)}"

    def _totp_stepup_index_key(self, user_id: str) -> str:
        """Return the Redis set key indexing TOTP step-up markers by user."""
        return f"{self.key_prefix}{_TOTP_STEPUP_SEGMENT}:user:{_safe_key_part(user_id)}"

    @staticmethod
    def _decode_user_id(value: RedisStoredValue) -> str:
        """Normalize Redis payloads to text identifiers.

        Returns:
            Decoded user identifier text.
        """
        if isinstance(value, bytes):
            return value.decode()
        return value

    @staticmethod
    def _encode_token_payload(*, epoch: int, user_id: str) -> str:
        """Return the Redis value stored for a token."""
        return f"{_PAYLOAD_FORMAT_VERSION}:{epoch}:{user_id}"

    @classmethod
    def _decode_token_payload(cls, value: RedisStoredValue) -> tuple[int, str] | None:
        """Return a current-format invalidation epoch and user id."""
        payload = cls._decode_user_id(value)
        version, separator, remainder = payload.partition(":")
        if version != _PAYLOAD_FORMAT_VERSION or not separator:
            return None
        epoch_text, epoch_separator, user_id = remainder.partition(":")
        if not epoch_separator or not user_id:
            return None
        try:
            epoch = int(epoch_text)
        except ValueError:
            return None
        return (epoch, user_id) if epoch >= 0 else None

    async def _current_user_epoch(self, user_id: str) -> int:
        """Return the current invalidation epoch for ``user_id``."""
        stored_epoch = await self.redis.get(self._user_epoch_key(user_id))
        if stored_epoch is None:
            return 0
        try:
            return int(self._decode_user_id(stored_epoch))
        except ValueError:
            return -1

    @property
    def _ttl_seconds(self) -> int:
        """The configured token lifetime rounded up to whole Redis seconds."""
        return max(ceil(self.lifetime.total_seconds()), 1)

    @property
    def _refresh_ttl_seconds(self) -> int:
        """The configured refresh lifetime rounded up to Redis seconds."""
        return max(ceil(self.refresh_lifetime.total_seconds()), 1)

    @staticmethod
    def _encode_refresh_payload(
        *,
        user_id: str,
        session_id: str,
        created_at: datetime,
        last_used_at: datetime | None,
        client_metadata: dict[str, str] | None,
    ) -> str:
        """Encode bounded refresh-session metadata.

        Returns:
            Canonical JSON payload.
        """
        return json.dumps(
            {
                "c": created_at.timestamp(),
                "l": None if last_used_at is None else last_used_at.timestamp(),
                "m": client_metadata,
                "s": session_id,
                "u": user_id,
                "v": _REFRESH_PAYLOAD_FORMAT_VERSION,
            },
            separators=(",", ":"),
            sort_keys=True,
        )

    @classmethod
    def _decode_refresh_payload(
        cls,
        value: RedisStoredValue,
    ) -> tuple[str, str, datetime, datetime | None, dict[str, str] | None] | None:
        """Decode and validate stored refresh-session metadata.

        Returns:
            Validated session fields, otherwise ``None``.
        """
        try:
            payload = json.loads(cls._decode_user_id(value))
            if not isinstance(payload, dict):
                return None
            if (
                payload.get("v") != _REFRESH_PAYLOAD_FORMAT_VERSION
                or not isinstance(payload.get("u"), str)
                or not isinstance(payload.get("s"), str)
                or not isinstance(payload.get("c"), int | float)
            ):
                return None
            if payload.get("l") is not None and not isinstance(payload.get("l"), int | float):
                return None
            if payload.get("m") is not None and not isinstance(payload.get("m"), dict):
                return None
            metadata = payload.get("m")
            if metadata is not None and not all(
                isinstance(key, str) and isinstance(item, str) for key, item in metadata.items()
            ):
                return None
            return (
                payload["u"],
                payload["s"],
                datetime.fromtimestamp(payload["c"], tz=UTC),
                None if payload["l"] is None else datetime.fromtimestamp(payload["l"], tz=UTC),
                metadata,
            )
        except (KeyError, TypeError, ValueError, json.JSONDecodeError):
            return None

    async def authenticate_token(
        self,
        token: str,
        user_manager: UserManagerProtocol[UP, ID],
    ) -> HumanSessionAuthenticated[UP] | Invalid | Unavailable:
        """Resolve a Redis session with an explicit terminal failure.

        Returns:
            Authenticated session metadata or a typed invalid decision.
        """
        try:
            stored_user_id = await self.redis.get(self._key(token))
        except self._redis_error:
            return Unavailable()
        if stored_user_id is None:
            return Invalid(FailureCode.INVALID)

        payload = self._decode_token_payload(stored_user_id)
        if payload is None:
            return Invalid(FailureCode.INVALID)
        token_epoch, user_id_text = payload
        try:
            current_epoch = await self._current_user_epoch(user_id_text)
        except self._redis_error:
            return Unavailable()
        if token_epoch != current_epoch:
            return Invalid(FailureCode.REVOKED)

        try:
            user_id = self.subject_decoder(user_id_text) if self.subject_decoder is not None else user_id_text
        except (TypeError, ValueError):
            return Invalid(FailureCode.INVALID)

        user = await user_manager.get(cast("ID", user_id))
        if user is None:
            return Invalid(FailureCode.INVALID)
        return HumanSessionAuthenticated(user=user)

    @override
    async def write_token(self, user: UP) -> str:
        """Persist a new opaque token in Redis and return it.

        Returns:
            Newly created opaque token string.
        """
        token, token_key = self._mint_token_key()
        user_id = str(user.id)
        epoch = await self._current_user_epoch(user_id)
        await self.redis.set(
            token_key,
            self._encode_token_payload(epoch=epoch, user_id=user_id),
            ex=self._ttl_seconds,
        )
        index_key = self._user_index_key(user_id)
        await self.redis.sadd(index_key, token_key)
        await self.redis.expire(index_key, self._ttl_seconds)
        return token

    async def write_token_for_session(self, user: UP, session_id: str) -> str:
        """Atomically issue an access token owned by an active refresh session.

        Returns:
            Newly issued opaque access token.

        Raises:
            ValueError: If the refresh session is no longer active.
        """
        token, token_key = self._mint_token_key()
        user_id = str(user.id)
        session_key = self._refresh_session_key(session_id)
        refresh_key = await self.redis.get(session_key)
        if refresh_key is None:
            msg = "Cannot issue an access token for an inactive refresh session."
            raise ValueError(msg)
        stored = await self.redis.get(self._decode_user_id(refresh_key))
        if stored is None:
            msg = "Cannot issue an access token for an inactive refresh session."
            raise ValueError(msg)
        decoded = self._decode_refresh_payload(stored)
        if decoded is None or decoded[0] != user_id or decoded[1] != session_id:
            msg = "Cannot issue an access token for an inactive refresh session."
            raise ValueError(msg)
        epoch = await self._current_user_epoch(user_id)
        created = await self.redis.eval(
            _REDIS_WRITE_SESSION_ACCESS_TOKEN_SCRIPT,
            4,
            session_key,
            self._decode_user_id(refresh_key),
            token_key,
            self._session_access_index_key(session_id),
            self._decode_user_id(stored),
            self._encode_token_payload(epoch=epoch, user_id=user_id),
            self._ttl_seconds,
        )
        if int(created) != 1:
            msg = "Cannot issue an access token for an inactive refresh session."
            raise ValueError(msg)
        index_key = self._user_index_key(user_id)
        await self.redis.sadd(index_key, token_key)
        await self.redis.expire(index_key, self._ttl_seconds)
        return token

    @override
    async def destroy_token(self, token: str, user: UP) -> None:
        """Delete a persisted Redis token."""
        token_key = self._key(token)
        user_id = str(user.id)
        index_key = self._user_index_key(user_id)
        await self.redis.delete(token_key)
        await self.redis.srem(index_key, token_key)

    async def write_refresh_token(self, user: UP) -> str:
        """Create a server-side refresh session and return its opaque credential.

        Returns:
            Newly issued opaque refresh token.
        """
        token, refresh_key = self._mint_refresh_token_key()
        user_id = str(user.id)
        session_id = str(uuid4())
        payload = self._encode_refresh_payload(
            user_id=user_id,
            session_id=session_id,
            created_at=datetime.now(tz=UTC),
            last_used_at=None,
            client_metadata=self._consume_refresh_token_request_metadata(),
        )
        await self.redis.set(refresh_key, payload, ex=self._refresh_ttl_seconds)
        await self.redis.set(
            self._refresh_session_key(session_id),
            refresh_key,
            ex=self._refresh_ttl_seconds,
        )
        user_index_key = self._refresh_user_index_key(user_id)
        await self.redis.sadd(user_index_key, self._refresh_session_key(session_id))
        await self.redis.expire(user_index_key, self._refresh_ttl_seconds)
        return token

    async def rotate_refresh_token(
        self,
        refresh_token: str,
        user_manager: UserManagerProtocol[UP, ID],
    ) -> tuple[UP, str] | None:
        """Atomically rotate a refresh token and revoke its chain on replay.

        Returns:
            User and replacement token, otherwise ``None``.
        """
        old_key = self._refresh_key(refresh_token)
        stored = await self.redis.get(old_key)
        if stored is None:
            await self._revoke_consumed_refresh_chain(refresh_token)
            return None
        decoded = self._decode_refresh_payload(stored)
        if decoded is None:
            await self.redis.delete(old_key)
            return None
        user_id_text, session_id, created_at, _, existing_metadata = decoded
        new_token, new_key = self._mint_refresh_token_key()
        new_payload = self._encode_refresh_payload(
            user_id=user_id_text,
            session_id=session_id,
            created_at=created_at,
            last_used_at=datetime.now(tz=UTC),
            client_metadata=self._consume_refresh_token_request_metadata() or existing_metadata,
        )
        rotated = await self.redis.eval(
            _REDIS_ROTATE_REFRESH_TOKEN_SCRIPT,
            5,
            old_key,
            new_key,
            self._refresh_consumed_key(refresh_token),
            self._refresh_session_key(session_id),
            self._session_access_index_key(session_id),
            self._decode_user_id(stored),
            new_payload,
            self._refresh_ttl_seconds,
            session_id,
        )
        if int(rotated) != 1:
            return None
        try:
            user_id = self.subject_decoder(user_id_text) if self.subject_decoder is not None else user_id_text
        except (TypeError, ValueError):
            await self._revoke_refresh_session_by_id(user_id_text, session_id)
            return None
        user = await user_manager.get(cast("ID", user_id))
        if user is None:
            await self._revoke_refresh_session_by_id(user_id_text, session_id)
            return None
        return user, new_token

    async def identify_refresh_session(self, user: UP, refresh_token: str) -> str | None:
        """Return the active session id owned by ``user`` for a refresh token."""
        stored = await self.redis.get(self._refresh_key(refresh_token))
        if stored is None:
            await self._revoke_consumed_refresh_chain(refresh_token)
            return None
        decoded = self._decode_refresh_payload(stored)
        if decoded is None or decoded[0] != str(user.id):
            return None
        return decoded[1]

    async def list_refresh_sessions(self, user: UP) -> list[RefreshSession]:
        """Return active refresh sessions owned by ``user``."""
        user_id = str(user.id)
        index_key = self._refresh_user_index_key(user_id)
        session_keys = await self.redis.smembers(index_key)
        sessions: list[RefreshSession] = []
        stale: list[str] = []
        for raw_session_key in session_keys:
            session_key = self._decode_user_id(raw_session_key)
            refresh_key = await self.redis.get(session_key)
            stored = None if refresh_key is None else await self.redis.get(self._decode_user_id(refresh_key))
            decoded = None if stored is None else self._decode_refresh_payload(stored)
            if decoded is None or decoded[0] != user_id:
                stale.append(session_key)
                continue
            _, session_id, created_at, last_used_at, metadata = decoded
            sessions.append(
                RefreshSession(
                    session_id=session_id,
                    created_at=created_at,
                    last_used_at=last_used_at,
                    client_metadata=metadata,
                ),
            )
        if stale:
            await self.redis.srem(index_key, *stale)
        return sorted(sessions, key=lambda session: session.created_at)

    async def revoke_refresh_session(self, user: UP, session_id: str) -> bool:
        """Revoke one refresh session owned by ``user``.

        Returns:
            Whether an active owned session was revoked.
        """
        return await self._revoke_refresh_session_by_id(str(user.id), session_id)

    async def revoke_other_refresh_sessions(self, user: UP, current_session_id: str | None) -> int:
        """Revoke all owned refresh sessions except the current session.

        Returns:
            Number of sessions revoked.
        """
        sessions = await self.list_refresh_sessions(user)
        revoked = 0
        for session in sessions:
            if session.session_id != current_session_id:
                revoked += await self.revoke_refresh_session(user, session.session_id)
        return revoked

    async def _revoke_refresh_session_by_id(self, user_id: str, session_id: str) -> bool:
        """Revoke one session and every access token linked to it.

        Returns:
            Whether the active session was revoked.
        """
        session_key = self._refresh_session_key(session_id)
        refresh_key = await self.redis.get(session_key)
        if refresh_key is None:
            return False
        stored = await self.redis.get(self._decode_user_id(refresh_key))
        decoded = None if stored is None else self._decode_refresh_payload(stored)
        if decoded is None or decoded[0] != user_id or decoded[1] != session_id:
            return False
        deleted = await self.redis.eval(
            _REDIS_REVOKE_REFRESH_SESSION_SCRIPT,
            3,
            session_key,
            self._session_access_index_key(session_id),
            self._refresh_user_index_key(user_id),
        )
        return int(deleted) == 1

    async def _revoke_consumed_refresh_chain(self, refresh_token: str) -> None:
        """Revoke the active chain when a consumed refresh token is replayed."""
        consumed_key = self._refresh_consumed_key(refresh_token)
        session_id = await self.redis.get(consumed_key)
        if session_id is None:
            return
        session_id_text = self._decode_user_id(session_id)
        session_key = self._refresh_session_key(session_id_text)
        refresh_key = await self.redis.get(session_key)
        if refresh_key is None:
            return
        stored = await self.redis.get(self._decode_user_id(refresh_key))
        decoded = None if stored is None else self._decode_refresh_payload(stored)
        if decoded is not None:
            await self._revoke_refresh_session_by_id(decoded[0], session_id_text)

    async def invalidate_all_tokens(self, user: UP) -> None:
        """Delete all Redis-backed tokens associated with the given user.

        This bumps a per-user invalidation epoch before deleting indexed token
        and step-up marker keys, so out-of-index tokens are rejected on their
        next read without requiring a keyspace scan.
        """
        user_id = str(user.id)
        await self.redis.eval(
            _REDIS_INVALIDATE_USER_TOKENS_SCRIPT,
            4,
            self._user_epoch_key(user_id),
            self._user_index_key(user_id),
            self._totp_stepup_index_key(user_id),
            self._refresh_user_index_key(user_id),
            self.key_prefix,
        )

    async def issue_totp_stepup(self, user: UP, session_id: str, *, ttl_seconds: int) -> None:
        """Store a short-lived TOTP step-up marker for a Redis-backed session."""
        user_id = str(user.id)
        key = self._totp_stepup_key(user_id, session_id)
        index_key = self._totp_stepup_index_key(user_id)
        if ttl_seconds <= 0:
            await self.redis.delete(key)
            await self.redis.srem(index_key, key)
            return
        await self.redis.set(key, "1", ex=ttl_seconds)
        await self.redis.sadd(index_key, key)
        await self.redis.expire(index_key, ttl_seconds)

    async def has_recent_totp_verification(self, user: UP, session_id: str) -> bool:
        """Return whether a Redis-backed session has a live TOTP step-up marker."""
        return await self.redis.get(self._totp_stepup_key(str(user.id), session_id)) is not None
