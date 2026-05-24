"""Refresh-token rotation helpers for database token strategies."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from typing import TYPE_CHECKING, Any, Protocol, cast

from sqlalchemy import delete, select, update

from litestar_auth.authentication.strategy._db_metadata import _DatabaseRefreshTokenMetadataMixin
from litestar_auth.authentication.strategy._db_time import _DatabaseTokenTimeMixin
from litestar_auth.authentication.strategy._opaque_tokens import mint_opaque_token
from litestar_auth.types import UserProtocol

if TYPE_CHECKING:
    from advanced_alchemy.repository import SQLAlchemyAsyncRepository
    from sqlalchemy.sql.base import Executable

    from litestar_auth.authentication.strategy._db_repositories import AsyncSessionT, TokenRepositoryType
    from litestar_auth.authentication.strategy.base import UserManagerProtocol


class _RefreshTokenRow(Protocol):
    """Persistence contract needed by refresh-token rotation."""

    token: str
    created_at: datetime
    session_id: str
    last_used_at: datetime | None
    client_metadata: dict[str, str] | None
    consumed_token_digests: list[str] | None
    user_id: object
    user: object


class _DatabaseRefreshTokenRotationMixin[UP: UserProtocol[Any], ID](
    _DatabaseTokenTimeMixin,
    _DatabaseRefreshTokenMetadataMixin,
):
    """Refresh-token rotation operations for database-backed sessions."""

    session: AsyncSessionT
    refresh_token_model: type[Any]
    refresh_max_age: timedelta
    token_bytes: int
    _token_hash_secret: bytes
    _refresh_token_repository_type: TokenRepositoryType

    def _repository(self, repository_type: TokenRepositoryType) -> SQLAlchemyAsyncRepository[Any]:
        """Create a repository bound to the current session."""
        raise NotImplementedError

    def _token_digest(self, token: str) -> str:
        """Return the keyed digest stored for a raw token."""
        raise NotImplementedError

    async def _execute_delete(self, statement: Executable) -> int:
        """Execute a delete/update statement and return its matched row count."""
        raise NotImplementedError

    async def _resolve_token(
        self,
        repository: SQLAlchemyAsyncRepository[Any],
        raw_token: str,
        *,
        load: list[Any],
    ) -> object | None:
        """Look up a token row by digest."""
        raise NotImplementedError

    async def _load_refresh_token_for_rotation(self, refresh_token: str) -> _RefreshTokenRow | None:
        """Load a refresh-token row for rotation.

        Returns:
            Persisted refresh-token row with its user loaded, otherwise ``None``.
        """
        return cast(
            "_RefreshTokenRow | None",
            await self._resolve_token(
                self._repository(self._refresh_token_repository_type),
                refresh_token,
                load=[self.refresh_token_model.user],
            ),
        )

    async def _delete_refresh_token_row(self, persisted_token: _RefreshTokenRow) -> None:
        """Mark a persisted refresh-token row for deletion within the current transaction."""
        await self._repository(self._refresh_token_repository_type).delete_where(
            token=persisted_token.token,
            auto_commit=False,
        )

    async def _find_refresh_token_row_by_consumed_digest(self, token_digest: str) -> _RefreshTokenRow | None:
        """Return the active refresh-session row that recorded ``token_digest`` as already consumed."""
        result = await self.session.execute(
            select(self.refresh_token_model).where(self.refresh_token_model.consumed_token_digests.is_not(None)),
        )
        rows = cast("list[_RefreshTokenRow]", result.scalars().all())
        return next((row for row in rows if token_digest in (row.consumed_token_digests or ())), None)

    async def _revoke_refresh_session_chain(self, session_id: str) -> None:
        """Delete every refresh-token row for a compromised refresh-session chain."""
        await self._execute_delete(
            delete(self.refresh_token_model).where(self.refresh_token_model.session_id == session_id),
        )

    async def _replace_refresh_token_digest(
        self,
        persisted_token: _RefreshTokenRow,
        *,
        consumed_token_digest: str,
        client_metadata: dict[str, str] | None,
    ) -> str | None:
        """Atomically replace a refresh-token digest and record the consumed digest.

        Returns:
            Newly created opaque refresh-token string, or ``None`` when another rotation already consumed it.
        """
        rotated_refresh_token, rotated_token_digest = mint_opaque_token(
            token_bytes=self.token_bytes,
            token_hash_secret=self._token_hash_secret,
        )
        consumed_token_digests = [*(persisted_token.consumed_token_digests or ()), consumed_token_digest]
        replaced_count = await self._execute_delete(
            update(self.refresh_token_model)
            .where(self.refresh_token_model.token == persisted_token.token)
            .values(
                token=rotated_token_digest,
                last_used_at=datetime.now(tz=UTC),
                client_metadata=client_metadata if client_metadata is not None else persisted_token.client_metadata,
                consumed_token_digests=consumed_token_digests,
            ),
        )
        if replaced_count != 1:
            compromised_row = await self._find_refresh_token_row_by_consumed_digest(consumed_token_digest)
            if compromised_row is not None:
                await self._revoke_refresh_session_chain(compromised_row.session_id)
            return None
        return rotated_refresh_token

    async def rotate_refresh_token(
        self,
        refresh_token: str,
        user_manager: UserManagerProtocol[UP, ID],
    ) -> tuple[UP, str] | None:
        """Rotate a refresh token and return the related user plus replacement.

        Returns:
            Tuple of the resolved user and rotated refresh token, or ``None`` when invalid.
        """
        del user_manager
        client_metadata = self._consume_refresh_token_request_metadata()
        token_digest = self._token_digest(refresh_token)
        persisted_token = await self._load_refresh_token_for_rotation(refresh_token)
        if persisted_token is None:
            compromised_row = await self._find_refresh_token_row_by_consumed_digest(token_digest)
            if compromised_row is not None:
                await self._revoke_refresh_session_chain(compromised_row.session_id)
                await self.session.commit()
            return None
        if self._is_token_expired(persisted_token.created_at, self.refresh_max_age):
            await self._delete_refresh_token_row(persisted_token)
            return None

        user = cast("UP", persisted_token.user)
        rotated_refresh_token = await self._replace_refresh_token_digest(
            persisted_token,
            consumed_token_digest=token_digest,
            client_metadata=client_metadata,
        )
        if rotated_refresh_token is None:
            return None
        return user, rotated_refresh_token
