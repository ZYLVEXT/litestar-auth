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
    RedisSetMembershipClient,
    RedisStoredValue,
    RedisValueReadClient,
)
from litestar_auth.authentication.strategy._opaque_tokens import build_opaque_token_key, mint_opaque_token
from litestar_auth.authentication.strategy.base import Strategy, UserManagerProtocol
from litestar_auth.config import validate_secret_length
from litestar_auth.exceptions import ConfigurationError
from litestar_auth.ratelimit._helpers import _safe_key_part
from litestar_auth.types import ID, UP

if TYPE_CHECKING:
    from collections.abc import Callable

DEFAULT_KEY_PREFIX = "litestar_auth:token:"
DEFAULT_LIFETIME = timedelta(hours=1)
DEFAULT_TOKEN_BYTES = 32

_load_redis_asyncio = partial(_require_redis_asyncio, feature_name="RedisTokenStrategy")


class RedisClientProtocol(
    RedisValueReadClient,
    RedisExpiringValueWriteClient,
    RedisDeleteClient,
    RedisSetMembershipClient,
    RedisKeyExpiryClient,
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
    def __init__(self, *, config: RedisTokenStrategyConfig[ID]) -> None:
        pass  # pragma: no cover

    @overload
    def __init__(self, **options: Unpack[RedisTokenStrategyOptions[ID]]) -> None:
        pass  # pragma: no cover

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
            validate_secret_length(settings.token_hash_secret, label="RedisTokenStrategy token_hash_secret")
        except ConfigurationError as exc:
            raise ConfigurationError(str(exc)) from exc

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

    @staticmethod
    def _decode_user_id(value: RedisStoredValue) -> str:
        """Normalize Redis payloads to text identifiers.

        Returns:
            Decoded user identifier text.
        """
        if isinstance(value, bytes):
            return value.decode()
        return value

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

        user_id_text = self._decode_user_id(stored_user_id)

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
        await self.redis.setex(token_key, self._ttl_seconds, user_id)
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

    async def _invalidate_via_index(self, user_id: str) -> None:
        """Invalidate tokens using the per-user Redis set index."""
        index_key = self._user_index_key(user_id)
        members = await self.redis.smembers(index_key)
        token_keys = [self._decode_user_id(member) for member in members] if members else []
        if not token_keys:
            return
        await self.redis.delete(*token_keys, index_key)

    async def invalidate_all_tokens(self, user: UP) -> None:
        """Delete all Redis-backed tokens associated with the given user.

        This uses a per-user index to delete only the keys associated with the
        user, avoiding keyspace scans under the global prefix. Tokens that do
        not have a per-user index entry are left to expire naturally by TTL.
        """
        await self._invalidate_via_index(str(user.id))
