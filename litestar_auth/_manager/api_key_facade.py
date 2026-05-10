"""API-key facade methods for the public user manager."""

from __future__ import annotations

from typing import TYPE_CHECKING, Any, Unpack

from litestar_auth.types import UserProtocol

if TYPE_CHECKING:
    from datetime import datetime

    from litestar_auth._manager.api_key_creation import ApiKeyCreateOptions
    from litestar_auth._manager.api_keys import ApiKeyManagerService, ApiKeyRowProtocol, CreatedApiKey


class ApiKeyManagerFacade[UP: UserProtocol[Any], ID]:
    """Mixin exposing API-key manager methods on ``BaseUserManager``."""

    _api_keys: ApiKeyManagerService[UP, ID]

    @property
    def api_keys(self) -> ApiKeyManagerService[UP, ID]:
        """Return the API-key service backing manager API-key operations."""
        return self._api_keys

    async def create_api_key(
        self,
        user: UP,
        **options: Unpack[ApiKeyCreateOptions],
    ) -> CreatedApiKey[ApiKeyRowProtocol]:
        """Create an API key and return the one-time raw credential.

        Returns:
            The persisted API-key row plus the one-time raw API key.
        """
        return await self._api_keys.create_api_key(
            user,
            **options,
        )

    async def list_api_keys(self, user: UP, *, include_inactive: bool = False) -> list[ApiKeyRowProtocol]:
        """Return API-key rows owned by ``user``."""
        return await self._api_keys.list_api_keys(user, include_inactive=include_inactive)

    async def get_api_key(self, user: UP, key_id: str, *, include_inactive: bool = False) -> ApiKeyRowProtocol:
        """Return one API-key row owned by ``user``."""
        return await self._api_keys.get_api_key(user, key_id, include_inactive=include_inactive)

    async def update_api_key(
        self,
        user: UP,
        key_id: str,
        *,
        name: str | None = None,
        scopes: tuple[str, ...] | list[str] | None = None,
        current_password: str | None = None,
    ) -> ApiKeyRowProtocol:
        """Update mutable API-key metadata owned by ``user``.

        Returns:
            The updated API-key row.
        """
        return await self._api_keys.update_api_key(
            user,
            key_id,
            name=name,
            scopes=scopes,
            current_password=current_password,
        )

    async def revoke_api_key(
        self,
        user: UP,
        key_id: str,
        *,
        revoked_at: datetime | None = None,
    ) -> ApiKeyRowProtocol:
        """Soft-revoke an API key owned by ``user``.

        Returns:
            The revoked API-key row.
        """
        return await self._api_keys.revoke_api_key(user, key_id, revoked_at=revoked_at)

    async def record_api_key_used(self, key_id: str, *, used_at: datetime | None = None) -> ApiKeyRowProtocol | None:
        """Record API-key use when configured and outside the throttle window.

        Returns:
            The updated API-key row, the unchanged row when throttled, or ``None``.
        """
        return await self._api_keys.record_api_key_used(key_id, used_at=used_at)

    def api_key_signing_secret_requires_reencrypt(self, api_key: ApiKeyRowProtocol) -> bool:
        """Return whether one API-key signing secret should be rewritten with the active key."""
        return self._api_keys.api_key_signing_secret_requires_reencrypt(api_key)

    async def reencrypt_api_key_signing_secret(self, api_key: ApiKeyRowProtocol | str) -> ApiKeyRowProtocol:
        """Rewrite one API-key signing secret under the active encryption key.

        Args:
            api_key: Either a loaded API-key row or a public ``key_id``.

        Returns:
            The updated API-key row.
        """
        return await self._api_keys.reencrypt_api_key_signing_secret(api_key)
