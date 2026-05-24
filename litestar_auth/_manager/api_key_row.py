"""API-key row and hook protocols."""

from __future__ import annotations

from typing import TYPE_CHECKING, Any, Protocol

if TYPE_CHECKING:
    from datetime import datetime


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


class _ApiKeyManagerHooks[UP](Protocol):  # noqa: PYI046
    """Lifecycle hooks invoked by API-key manager operations."""

    async def on_after_api_key_created(self, user: UP, api_key: object) -> None:  # pragma: no cover
        """Run after an API key has been created."""

    async def on_after_api_key_revoked(self, user: UP, api_key: object) -> None:  # pragma: no cover
        """Run after an API key has been revoked."""

    async def on_after_api_key_used(self, api_key: object) -> None:  # pragma: no cover
        """Run after an API-key last-used write is persisted."""


class _ApiKeyManagerProtocol[UP](Protocol):  # noqa: PYI046
    """Manager surface required by API-key service operations."""

    api_key_hash_secret: Any
    password_helper: Any
