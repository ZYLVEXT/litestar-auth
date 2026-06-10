"""API-key manager service operations."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from typing import TYPE_CHECKING, Any, Unpack, cast

import litestar_auth._manager.api_key_creation as _api_key_creation
import litestar_auth._manager.api_key_secrets as _api_key_secrets
from litestar_auth._manager.api_key_config import (
    ApiKeyConfigProtocol,
    ApiKeyManagerConfig,
    coerce_api_key_manager_config,
    resolve_api_key_expires_at,
)
from litestar_auth._manager.hooks import ManagerHookBus
from litestar_auth.authentication.strategy._api_key_format import digest_api_key_secret
from litestar_auth.db.base import ApiKeyData
from litestar_auth.exceptions import ApiKeyError, ApiKeyLimitReachedError, ApiKeyNotFoundError, ApiKeyScopeDeniedError
from litestar_auth.types import UserProtocol

if TYPE_CHECKING:
    from collections.abc import Sequence

    from litestar_auth._manager.api_key_row import ApiKeyRowProtocol, _ApiKeyManagerProtocol
    from litestar_auth.db.base import BaseApiKeyStore


class ApiKeyManagerService[UP: UserProtocol[Any], ID]:
    """Coordinate API-key issuance, metadata updates, revocation, and use tracking."""

    def __init__(
        self,
        manager: _ApiKeyManagerProtocol[UP],
        *,
        api_key_store: BaseApiKeyStore[Any, ID] | None,
        config: ApiKeyManagerConfig | ApiKeyConfigProtocol | None,
        hook_bus: ManagerHookBus[UP] | None = None,
    ) -> None:
        """Bind API-key persistence and policy for one manager instance."""
        self._manager = manager
        self._store = api_key_store
        self._config = coerce_api_key_manager_config(config)
        self._hook_bus = hook_bus or ManagerHookBus(manager)

    async def create_api_key(
        self,
        user: UP,
        **options: Unpack[_api_key_creation.ApiKeyCreateOptions],
    ) -> _api_key_secrets.ApiKeyCreateResult[ApiKeyRowProtocol]:
        """Create an API key and return the one-time raw credential."""  # noqa: DOC201, DOC501
        data = _api_key_creation.coerce_api_key_create_options(options)
        self._verify_current_password_if_supplied(user, data.current_password)
        normalized_scopes = self._normalize_requested_scopes(data.scopes)
        store = self._require_store()
        user_id = cast("ID", user.id)
        key_id = self._generate_key_id()
        secret = self._generate_secret()
        raw_api_key = f"{self._config.prefix}_{self._config.environment_marker}_{key_id}.{secret}"
        encrypted_secret = (
            _api_key_secrets.encrypt_secret_for_signing(secret, self._config.secret_encryption_keyring)
            if data.signing_required
            else None
        )
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
                    expires_at=resolve_api_key_expires_at(self._config, data.expires_at),
                    created_via=data.created_via,
                    client_metadata=data.client_metadata,
                ),
                max_keys_per_user=self._config.max_keys_per_user,
            ),
        )
        if created is None:
            raise ApiKeyLimitReachedError(max_keys_per_user=self._config.max_keys_per_user)
        await self._hook_bus.fire("after_api_key_created", user, created)
        return _api_key_secrets.ApiKeyCreateResult(
            api_key=created,
            secret=_api_key_secrets.ApiKeySecret(raw_api_key),
        )

    async def list_api_keys(self, user: UP, *, include_inactive: bool = False) -> list[ApiKeyRowProtocol]:
        """Return API-key rows owned by ``user``."""
        return cast(
            "list[ApiKeyRowProtocol]",
            await self._require_store().list_for_user(cast("ID", user.id), include_inactive=include_inactive),
        )

    async def get_api_key(self, user: UP, key_id: str, *, include_inactive: bool = False) -> ApiKeyRowProtocol:
        """Return one API-key row owned by ``user``."""  # noqa: DOC501
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
        """Update mutable API-key metadata owned by ``user``."""  # noqa: DOC201, DOC501
        self._verify_current_password_if_supplied(user, current_password)
        api_key = await self.get_api_key(user, key_id)
        normalized_scopes = None if scopes is None else self._normalize_requested_scopes(scopes)
        if name is None and normalized_scopes is None:
            return api_key
        updated = cast(
            "ApiKeyRowProtocol | None",
            await self._require_store().update(key_id, name=name, scopes=normalized_scopes),
        )
        if updated is None:
            raise ApiKeyNotFoundError
        return updated

    async def revoke_api_key(self, user: UP, key_id: str, *, revoked_at: datetime | None = None) -> ApiKeyRowProtocol:
        """Soft-revoke an API key owned by ``user`` and keep repeated revocation idempotent."""  # noqa: DOC201, DOC501
        await self.get_api_key(user, key_id, include_inactive=True)
        api_key = cast(
            "ApiKeyRowProtocol | None",
            await self._require_store().revoke(key_id, revoked_at=revoked_at or datetime.now(tz=UTC)),
        )
        if api_key is None or api_key.user_id != user.id:
            raise ApiKeyNotFoundError
        await self._hook_bus.fire("after_api_key_revoked", user, api_key)
        return api_key

    async def record_api_key_used(self, key_id: str, *, used_at: datetime | None = None) -> ApiKeyRowProtocol | None:
        """Record API-key use when configured and outside the throttle window."""  # noqa: DOC201
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
            await self._hook_bus.fire("after_api_key_used", updated)
        return updated

    def api_key_signing_secret_requires_reencrypt(self, api_key: ApiKeyRowProtocol) -> bool:
        """Return whether one signing API-key encrypted secret needs active-key rotation."""
        self._require_store()
        keyring = _api_key_secrets.require_secret_encryption_keyring(self._config.secret_encryption_keyring)
        encrypted_secret = _api_key_secrets.require_rotation_encrypted_secret(api_key)
        return _api_key_secrets.signing_secret_needs_rotation(keyring, encrypted_secret)

    async def reencrypt_api_key_signing_secret(self, api_key: ApiKeyRowProtocol | str) -> ApiKeyRowProtocol:
        """Rewrite one API-key signing secret under the active encryption key."""  # noqa: DOC201, DOC501
        store = self._require_store()
        resolved_api_key = await self._resolve_rotation_api_key(api_key, store)
        keyring = _api_key_secrets.require_secret_encryption_keyring(self._config.secret_encryption_keyring)
        encrypted_secret = _api_key_secrets.require_rotation_encrypted_secret(resolved_api_key)
        plaintext_secret = _api_key_secrets.decrypt_rotation_secret(keyring, encrypted_secret)
        updated = cast(
            "ApiKeyRowProtocol | None",
            await store.replace_signing_key_encrypted_secret(
                resolved_api_key.key_id,
                encrypted_secret=keyring.encrypt(plaintext_secret).encode("utf-8"),
            ),
        )
        if updated is None:
            raise ApiKeyNotFoundError
        return updated

    def _normalize_requested_scopes(self, scopes: Sequence[str]) -> list[str]:
        requested = tuple(dict.fromkeys(scope.strip() for scope in scopes if scope.strip()))
        if not self._config.scope_subset_check:
            return list(requested)
        denied = frozenset(requested) - frozenset(self._config.allowed_scopes)
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

    def _should_write_last_used(self, api_key: ApiKeyRowProtocol, used_at: datetime) -> bool:
        if api_key.last_used_at is None:
            return True
        return used_at - _api_key_secrets.as_aware_utc(api_key.last_used_at) >= timedelta(
            seconds=self._config.last_used_throttle_seconds,
        )

    @staticmethod
    def _generate_key_id() -> str:
        return _api_key_secrets.generate_key_id()

    @staticmethod
    def _generate_secret() -> str:
        return _api_key_secrets.generate_secret()
