"""Redis-backed authentication strategy."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import timedelta
from functools import partial
from typing import TYPE_CHECKING, NotRequired, Protocol, Required, TypedDict, Unpack, cast, overload, override

from litestar_auth._optional_deps import _require_redis_asyncio
from litestar_auth._redis_protocols import (
    RedisDeleteClient,
    RedisExpiringValueWriteClient,
    RedisKeyExpiryClient,
    RedisScriptEvalClient,
    RedisSetMembershipClient,
    RedisStoredValue,
    RedisValueReadClient,
)
from litestar_auth.authentication.strategy._opaque_tokens import (
    build_opaque_token_key,
    mint_opaque_token,
    validate_token_bytes,
)
from litestar_auth.authentication.strategy.base import Strategy, UserManagerProtocol
from litestar_auth.config import validate_production_secret
from litestar_auth.exceptions import ConfigurationError
from litestar_auth.ratelimit._key_derivation import _safe_key_part
from litestar_auth.types import ID, UP

if TYPE_CHECKING:
    from collections.abc import Callable

DEFAULT_KEY_PREFIX = "litestar_auth:token:"
DEFAULT_LIFETIME = timedelta(hours=1)
DEFAULT_TOKEN_BYTES = 32
_TOTP_STEPUP_SEGMENT = "totp_stepup"
_PAYLOAD_FORMAT_VERSION = "v1"

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

return 1
"""

_load_redis_asyncio = partial(_require_redis_asyncio, feature_name="RedisTokenStrategy")


class RedisClientProtocol(
    RedisValueReadClient,
    RedisExpiringValueWriteClient,
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
    token_bytes: int = DEFAULT_TOKEN_BYTES
    key_prefix: str = DEFAULT_KEY_PREFIX
    subject_decoder: Callable[[str], ID] | None = None


class RedisTokenStrategyOptions[ID](TypedDict):
    """Keyword options accepted by :class:`RedisTokenStrategy`."""

    redis: Required[RedisClientProtocol]
    token_hash_secret: Required[str]
    lifetime: NotRequired[timedelta]
    token_bytes: NotRequired[int]
    key_prefix: NotRequired[str]
    subject_decoder: NotRequired[Callable[[str], ID] | None]


class RedisTokenStrategy(Strategy[UP, ID]):
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
        try:
            validate_production_secret(settings.token_hash_secret, label="RedisTokenStrategy token_hash_secret")
        except ConfigurationError as exc:
            raise ConfigurationError(str(exc)) from exc
        validate_token_bytes(settings.token_bytes, label="RedisTokenStrategy")

        self.redis = settings.redis
        self._token_hash_secret = settings.token_hash_secret.encode()
        self.lifetime = settings.lifetime
        self.token_bytes = settings.token_bytes
        self.key_prefix = settings.key_prefix
        self.subject_decoder = settings.subject_decoder

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
    def _decode_token_payload(cls, value: RedisStoredValue) -> tuple[int, str]:
        """Return the stored invalidation epoch and user id.

        Legacy token values were stored as the raw user id. Treat those values as
        epoch ``0`` so they are rejected after the user's first epoch bump.
        """
        payload = cls._decode_user_id(value)
        version, separator, remainder = payload.partition(":")
        if version != _PAYLOAD_FORMAT_VERSION or not separator:
            return 0, payload
        epoch_text, epoch_separator, user_id = remainder.partition(":")
        if not epoch_separator:
            return 0, payload
        try:
            return int(epoch_text), user_id
        except ValueError:
            return 0, payload

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
        """Return the configured token lifetime in whole seconds."""
        return max(int(self.lifetime.total_seconds()), 1)

    @override
    async def read_token(
        self,
        token: str | None,
        user_manager: UserManagerProtocol[UP, ID],
    ) -> UP | None:
        """Resolve a user from a Redis-backed token.

        Returns:
            The resolved user when the token exists and decodes successfully,
            otherwise ``None``.
        """
        if token is None:
            return None

        stored_user_id = await self.redis.get(self._key(token))
        if stored_user_id is None:
            return None

        token_epoch, user_id_text = self._decode_token_payload(stored_user_id)
        if token_epoch != await self._current_user_epoch(user_id_text):
            return None

        try:
            user_id = self.subject_decoder(user_id_text) if self.subject_decoder is not None else user_id_text
        except (TypeError, ValueError):
            return None

        return await user_manager.get(cast("ID", user_id))

    @override
    async def write_token(self, user: UP) -> str:
        """Persist a new opaque token in Redis and return it.

        Returns:
            Newly created opaque token string.
        """
        token, token_key = self._mint_token_key()
        user_id = str(user.id)
        epoch = await self._current_user_epoch(user_id)
        await self.redis.setex(token_key, self._ttl_seconds, self._encode_token_payload(epoch=epoch, user_id=user_id))
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

    async def invalidate_all_tokens(self, user: UP) -> None:
        """Delete all Redis-backed tokens associated with the given user.

        This bumps a per-user invalidation epoch before deleting indexed token
        and step-up marker keys, so out-of-index tokens are rejected on their
        next read without requiring a keyspace scan.
        """
        user_id = str(user.id)
        await self.redis.eval(
            _REDIS_INVALIDATE_USER_TOKENS_SCRIPT,
            3,
            self._user_epoch_key(user_id),
            self._user_index_key(user_id),
            self._totp_stepup_index_key(user_id),
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
        await self.redis.setex(key, ttl_seconds, "1")
        await self.redis.sadd(index_key, key)
        await self.redis.expire(index_key, ttl_seconds)

    async def has_recent_totp_verification(self, user: UP, session_id: str) -> bool:
        """Return whether a Redis-backed session has a live TOTP step-up marker."""
        return await self.redis.get(self._totp_stepup_key(str(user.id), session_id)) is not None
