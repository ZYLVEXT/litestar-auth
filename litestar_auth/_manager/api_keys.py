"""API-key manager operations."""

from __future__ import annotations

import secrets
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from typing import TYPE_CHECKING, Any, Literal, Protocol, Unpack, cast

from litestar_auth._manager import api_key_creation as _api_key_creation
from litestar_auth._plugin.feature_configs import DEFAULT_API_KEY_LAST_USED_THROTTLE_SECONDS
from litestar_auth._secrets_at_rest import FernetKeyring, SecretAtRestError
from litestar_auth.authentication.strategy._api_key_format import API_KEY_PREFIX, digest_api_key_secret
from litestar_auth.db.base import ApiKeyData
from litestar_auth.exceptions import ApiKeyError, ApiKeyLimitReachedError, ApiKeyNotFoundError, ApiKeyScopeDeniedError

if TYPE_CHECKING:
    from collections.abc import Sequence

    from litestar_auth.db.base import BaseApiKeyStore
    from litestar_auth.types import UserProtocol


type ApiKeyLastUsedWriteStrategy = Literal["disabled", "immediate", "throttled"]

_DEFAULT_KEY_ID_BYTES = 16
_DEFAULT_SECRET_BYTES = 32


@dataclass(frozen=True, slots=True)
class ApiKeyManagerConfig:
    """Manager-owned API-key policy inputs."""

    prefix: str = API_KEY_PREFIX
    environment_marker: str = "prod"
    max_keys_per_user: int = 5
    default_ttl: timedelta | None = timedelta(days=365)
    allowed_scopes: Sequence[str] = ()
    scope_subset_check: bool = True
    last_used_write_strategy: ApiKeyLastUsedWriteStrategy = "throttled"
    last_used_throttle_seconds: int = DEFAULT_API_KEY_LAST_USED_THROTTLE_SECONDS
    secret_encryption_keyring: FernetKeyring | None = None


@dataclass(frozen=True, slots=True)
class ApiKeySecret:
    """One-time API-key credential whose repr/str never reveal the secret."""

    _value: str

    def get_secret_value(self) -> str:
        """Return the raw API key for the one response that is allowed to expose it."""
        return self._value

    def __repr__(self) -> str:
        """Return a redacted representation."""
        return "ApiKeySecret('**********')"

    def __str__(self) -> str:
        """Return a redacted string representation."""
        return "**********"


@dataclass(frozen=True, slots=True)
class CreatedApiKey[AK]:
    """API-key creation result carrying the one-time raw credential."""

    api_key: AK
    secret: ApiKeySecret


class ApiKeyConfigProtocol(Protocol):
    """Structural subset of plugin API-key config consumed by the manager."""

    prefix: str
    environment_marker: str
    max_keys_per_user: int
    default_ttl: timedelta | None
    allowed_scopes: Sequence[str]
    scope_subset_check: bool
    last_used_write_strategy: ApiKeyLastUsedWriteStrategy
    last_used_throttle_seconds: int
    secret_encryption_keyring: object | None


class ApiKeyRowProtocol(Protocol):
    """API-key row fields consumed by manager operations."""

    key_id: str
    user_id: object
    hashed_secret: bytes
    encrypted_secret: bytes | None
    signing_required: bool
    name: str
    scopes: list[str]
    prefix_env: str
    expires_at: datetime | None
    last_used_at: datetime | None
    revoked_at: datetime | None
    client_metadata: dict[str, str] | None


class _ApiKeyManagerHooks[UP](Protocol):
    """Lifecycle hooks invoked by API-key manager operations."""

    async def on_after_api_key_created(self, user: UP, api_key: object) -> None:  # pragma: no cover
        """Run after an API key has been created."""

    async def on_after_api_key_revoked(self, user: UP, api_key: object) -> None:  # pragma: no cover
        """Run after an API key has been revoked."""

    async def on_after_api_key_used(self, api_key: object) -> None:  # pragma: no cover
        """Run after an API-key last-used write is persisted."""


class _ApiKeyManagerProtocol[UP: UserProtocol[Any]](_ApiKeyManagerHooks[UP], Protocol):
    """Manager surface required by :class:`ApiKeyManagerService`."""

    api_key_hash_secret: Any
    password_helper: Any


class ApiKeyManagerService[UP: UserProtocol[Any], ID]:
    """Coordinate API-key issuance, metadata updates, revocation, and use tracking."""

    def __init__(
        self,
        manager: _ApiKeyManagerProtocol[UP],
        *,
        api_key_store: BaseApiKeyStore[Any, ID] | None,
        config: ApiKeyManagerConfig | ApiKeyConfigProtocol | None,
    ) -> None:
        """Bind API-key persistence and policy for one manager instance."""
        self._manager = manager
        self._store = api_key_store
        self._config = _coerce_api_key_manager_config(config)

    async def create_api_key(
        self,
        user: UP,
        **options: Unpack[_api_key_creation.ApiKeyCreateOptions],
    ) -> CreatedApiKey[ApiKeyRowProtocol]:
        """Create an API key and return the one-time raw credential.

        Returns:
            The persisted API-key row plus the one-time raw API key.

        Raises:
            ApiKeyLimitReachedError: If the user has reached the active-key limit.
        """
        data = _api_key_creation.coerce_api_key_create_options(options)
        self._verify_current_password_if_supplied(user, data.current_password)
        normalized_scopes = self._normalize_requested_scopes(data.scopes)
        store = self._require_store()
        user_id = cast("ID", user.id)
        key_id = self._generate_key_id()
        secret = self._generate_secret()
        raw_api_key = f"{self._config.prefix}_{self._config.environment_marker}_{key_id}.{secret}"
        encrypted_secret = self._encrypt_secret_for_signing(secret) if data.signing_required else None
        created = cast(
            "ApiKeyRowProtocol | None",
            await store.create_for_user_with_limit(
                ApiKeyData(
                    key_id=key_id,
                    user_id=user_id,
                    hashed_secret=digest_api_key_secret(
                        api_key_hash_secret=self._require_hash_secret(),
                        secret=secret,
                    ),
                    encrypted_secret=encrypted_secret,
                    name=data.name,
                    scopes=normalized_scopes,
                    prefix_env=self._config.environment_marker,
                    signing_required=data.signing_required,
                    expires_at=self._resolve_expires_at(data.expires_at),
                    created_via=data.created_via,
                    client_metadata=data.client_metadata,
                ),
                max_keys_per_user=self._config.max_keys_per_user,
            ),
        )
        if created is None:
            raise ApiKeyLimitReachedError(max_keys_per_user=self._config.max_keys_per_user)
        await self._manager.on_after_api_key_created(user, created)
        return CreatedApiKey(api_key=created, secret=ApiKeySecret(raw_api_key))

    async def list_api_keys(self, user: UP, *, include_inactive: bool = False) -> list[ApiKeyRowProtocol]:
        """Return API-key rows owned by ``user``."""
        return cast(
            "list[ApiKeyRowProtocol]",
            await self._require_store().list_for_user(cast("ID", user.id), include_inactive=include_inactive),
        )

    async def get_api_key(self, user: UP, key_id: str, *, include_inactive: bool = False) -> ApiKeyRowProtocol:
        """Return one API-key row owned by ``user`` or raise a structured error.

        Raises:
            ApiKeyNotFoundError: If no matching user-owned API key exists.
        """
        api_key = cast(
            "ApiKeyRowProtocol | None",
            await self._require_store().get_by_key_id(key_id, include_inactive=include_inactive),
        )
        if api_key is None or api_key.user_id != user.id:
            raise ApiKeyNotFoundError
        return api_key

    async def update_api_key(
        self,
        user: UP,
        key_id: str,
        *,
        name: str | None = None,
        scopes: Sequence[str] | None = None,
        current_password: str | None = None,
    ) -> ApiKeyRowProtocol:
        """Update mutable API-key metadata owned by ``user``.

        Returns:
            The updated API-key row.

        Raises:
            ApiKeyNotFoundError: If no matching user-owned API key exists.
        """
        self._verify_current_password_if_supplied(user, current_password)
        api_key = await self.get_api_key(user, key_id)
        normalized_scopes = None if scopes is None else self._normalize_requested_scopes(scopes)
        if name is None and normalized_scopes is None:
            return api_key
        store = self._require_store()
        updated = cast("ApiKeyRowProtocol | None", await store.update(key_id, name=name, scopes=normalized_scopes))
        if updated is None:
            raise ApiKeyNotFoundError
        return updated

    async def revoke_api_key(self, user: UP, key_id: str, *, revoked_at: datetime | None = None) -> ApiKeyRowProtocol:
        """Soft-revoke an API key owned by ``user`` and keep repeated revocation idempotent.

        Returns:
            The revoked API-key row.

        Raises:
            ApiKeyNotFoundError: If no matching user-owned API key exists.
        """
        await self.get_api_key(user, key_id, include_inactive=True)
        api_key = cast(
            "ApiKeyRowProtocol | None",
            await self._require_store().revoke(key_id, revoked_at=revoked_at or datetime.now(tz=UTC)),
        )
        if api_key is None or api_key.user_id != user.id:
            raise ApiKeyNotFoundError
        await self._manager.on_after_api_key_revoked(user, api_key)
        return api_key

    async def record_api_key_used(self, key_id: str, *, used_at: datetime | None = None) -> ApiKeyRowProtocol | None:
        """Record API-key use when configured and outside the throttle window.

        Returns:
            The updated API-key row, the unchanged row when throttled, or ``None``.
        """
        if self._config.last_used_write_strategy == "disabled":
            return None
        store = self._require_store()
        api_key = cast("ApiKeyRowProtocol | None", await store.get_by_key_id(key_id))
        if api_key is None:
            return None
        now = used_at or datetime.now(tz=UTC)
        if self._config.last_used_write_strategy == "throttled" and not self._should_write_last_used(api_key, now):
            return api_key
        updated = cast("ApiKeyRowProtocol | None", await store.update_last_used_at(key_id, last_used_at=now))
        if updated is not None:
            await self._manager.on_after_api_key_used(updated)
        return updated

    def api_key_signing_secret_requires_reencrypt(self, api_key: ApiKeyRowProtocol) -> bool:
        """Return whether one signing API-key encrypted secret needs active-key rotation."""
        self._require_store()
        keyring = self._require_secret_encryption_keyring()
        encrypted_secret = self._require_rotation_encrypted_secret(api_key)
        return self._signing_secret_needs_rotation(keyring, encrypted_secret)

    async def reencrypt_api_key_signing_secret(self, api_key: ApiKeyRowProtocol | str) -> ApiKeyRowProtocol:
        """Rewrite one API-key signing secret under the active encryption key.

        Args:
            api_key: Either a loaded API-key row or a public ``key_id``. Raw bearer API-key strings
                are rejected and never parsed for secret material.

        Returns:
            The updated API-key row.

        Raises:
            ApiKeyNotFoundError: If the supplied ``key_id`` does not resolve to an API-key row.
        """
        store = self._require_store()
        resolved_api_key = await self._resolve_rotation_api_key(api_key, store)
        keyring = self._require_secret_encryption_keyring()
        encrypted_secret = self._require_rotation_encrypted_secret(resolved_api_key)
        plaintext_secret = self._decrypt_rotation_secret(keyring, encrypted_secret)
        rewritten_secret = keyring.encrypt(plaintext_secret).encode("utf-8")
        updated = cast(
            "ApiKeyRowProtocol | None",
            await store.replace_signing_key_encrypted_secret(
                resolved_api_key.key_id,
                encrypted_secret=rewritten_secret,
            ),
        )
        if updated is None:
            raise ApiKeyNotFoundError
        return updated

    def _normalize_requested_scopes(self, scopes: Sequence[str]) -> list[str]:
        requested = tuple(dict.fromkeys(scope.strip() for scope in scopes if scope.strip()))
        if not self._config.scope_subset_check:
            return list(requested)
        allowed = frozenset(self._config.allowed_scopes)
        denied = frozenset(requested) - allowed
        if denied:
            raise ApiKeyScopeDeniedError(denied_scopes=denied)
        return list(requested)

    def _verify_current_password_if_supplied(self, user: UP, current_password: str | None) -> None:
        if current_password is None:
            return
        hashed_password = getattr(user, "hashed_password", None)
        if not isinstance(hashed_password, str) or not self._manager.password_helper.verify(
            current_password,
            hashed_password,
        ):
            from litestar_auth.exceptions import InvalidPasswordError  # noqa: PLC0415

            raise InvalidPasswordError(user_id=user.id)

    def _require_store(self) -> BaseApiKeyStore[Any, ID]:
        if self._store is None:
            msg = "API-key manager operations require api_key_store."
            raise ApiKeyError(msg)
        return self._store

    def _require_hash_secret(self) -> bytes:
        secret = self._manager.api_key_hash_secret
        get_secret_value = getattr(secret, "get_secret_value", None)
        if callable(get_secret_value):
            return cast("str", get_secret_value()).encode()
        if isinstance(secret, str):
            return secret.encode()
        msg = "API-key manager operations require api_key_hash_secret."
        raise ApiKeyError(msg)

    def _encrypt_secret_for_signing(self, secret: str) -> bytes:
        keyring = self._config.secret_encryption_keyring
        if keyring is None:
            msg = "API-key signing requires api_keys.secret_encryption_keyring."
            raise ApiKeyError(msg)
        return keyring.encrypt(secret).encode("utf-8")

    def _require_secret_encryption_keyring(self) -> FernetKeyring:
        keyring = self._config.secret_encryption_keyring
        if keyring is None:
            msg = "API-key signing-secret rotation requires api_keys.secret_encryption_keyring."
            raise ApiKeyError(msg)
        return keyring

    async def _resolve_rotation_api_key(
        self,
        api_key: ApiKeyRowProtocol | str,
        store: BaseApiKeyStore[Any, ID],
    ) -> ApiKeyRowProtocol:
        if not isinstance(api_key, str):
            return api_key
        if "." in api_key or api_key.startswith(f"{self._config.prefix}_{self._config.environment_marker}_"):
            msg = "API-key signing-secret rotation requires a signing API-key row or key_id."
            raise ApiKeyError(msg)
        resolved = cast("ApiKeyRowProtocol | None", await store.get_by_key_id(api_key, include_inactive=True))
        if resolved is None:
            raise ApiKeyNotFoundError
        return resolved

    @staticmethod
    def _require_rotation_encrypted_secret(api_key: ApiKeyRowProtocol) -> bytes:
        if not api_key.signing_required or api_key.encrypted_secret is None:
            msg = "API-key signing-secret rotation requires an encrypted signing API key."
            raise ApiKeyError(msg)
        return api_key.encrypted_secret

    @staticmethod
    def _signing_secret_needs_rotation(keyring: FernetKeyring, encrypted_secret: bytes) -> bool:
        try:
            return keyring.needs_rotation(encrypted_secret.decode("utf-8"))
        except (SecretAtRestError, UnicodeDecodeError) as exc:
            msg = "API-key signing secret cannot be processed for rotation."
            raise ApiKeyError(msg) from exc

    @staticmethod
    def _decrypt_rotation_secret(keyring: FernetKeyring, encrypted_secret: bytes) -> str:
        try:
            return keyring.decrypt(encrypted_secret.decode("utf-8"))
        except (SecretAtRestError, UnicodeDecodeError) as exc:
            msg = "API-key signing secret cannot be processed for rotation."
            raise ApiKeyError(msg) from exc

    def _resolve_expires_at(self, expires_at: datetime | None) -> datetime | None:
        if expires_at is not None:
            return expires_at
        if self._config.default_ttl is None:
            return None
        return datetime.now(tz=UTC) + self._config.default_ttl

    def _should_write_last_used(self, api_key: ApiKeyRowProtocol, used_at: datetime) -> bool:
        if api_key.last_used_at is None:
            return True
        last_used_at = _as_aware_utc(api_key.last_used_at)
        return used_at - last_used_at >= timedelta(seconds=self._config.last_used_throttle_seconds)

    @staticmethod
    def _generate_key_id() -> str:
        key_id = secrets.token_urlsafe(_DEFAULT_KEY_ID_BYTES)
        if key_id[0].isalnum():
            return key_id
        return f"k{key_id[1:]}"

    @staticmethod
    def _generate_secret() -> str:
        return secrets.token_urlsafe(_DEFAULT_SECRET_BYTES)


def _coerce_api_key_manager_config(config: ApiKeyManagerConfig | ApiKeyConfigProtocol | None) -> ApiKeyManagerConfig:
    if config is None:
        return ApiKeyManagerConfig()
    if isinstance(config, ApiKeyManagerConfig):
        return config
    return ApiKeyManagerConfig(
        prefix=config.prefix,
        environment_marker=config.environment_marker,
        max_keys_per_user=config.max_keys_per_user,
        default_ttl=config.default_ttl,
        allowed_scopes=config.allowed_scopes,
        scope_subset_check=config.scope_subset_check,
        last_used_write_strategy=config.last_used_write_strategy,
        last_used_throttle_seconds=config.last_used_throttle_seconds,
        secret_encryption_keyring=_coerce_fernet_keyring(getattr(config, "secret_encryption_keyring", None)),
    )


def _as_aware_utc(value: datetime) -> datetime:
    if value.tzinfo is None:
        return value.replace(tzinfo=UTC)
    return value.astimezone(UTC)


def _coerce_fernet_keyring(configured: object) -> FernetKeyring | None:
    if configured is None:
        return None
    if isinstance(configured, FernetKeyring):
        return configured
    active_key_id = getattr(configured, "active_key_id", None)
    keys = getattr(configured, "keys", None)
    if isinstance(active_key_id, str) and keys is not None:
        return FernetKeyring(active_key_id=active_key_id, keys=keys)
    msg = "api_keys.secret_encryption_keyring must be a FernetKeyringConfig."
    raise ApiKeyError(msg)
