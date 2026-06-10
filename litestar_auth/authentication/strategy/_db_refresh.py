"""Refresh-session operations for database token strategies."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from typing import TYPE_CHECKING, Any, cast

from sqlalchemy import delete, select

from litestar_auth.authentication.strategy._db_metadata import (
    _CLIENT_METADATA_TOTP_STEPUP_EXPIRES_AT_KEY,
)
from litestar_auth.authentication.strategy._db_rotation import _DatabaseRefreshTokenRotationMixin, _RefreshTokenRow
from litestar_auth.authentication.strategy.base import RefreshSession
from litestar_auth.types import UserProtocol

if TYPE_CHECKING:
    from collections.abc import Iterable

    from advanced_alchemy.repository import SQLAlchemyAsyncRepository
    from sqlalchemy.sql.base import Executable
    from sqlalchemy.sql.roles import InElementRole

    from litestar_auth.authentication.strategy._db_repositories import AsyncSessionT, TokenRepositoryType
    from litestar_auth.authentication.strategy.db_models import RefreshTokenConsumedDigest


class _DatabaseRefreshSessionMixin[UP: UserProtocol[Any], ID](
    _DatabaseRefreshTokenRotationMixin[UP, ID],
):
    """Database refresh-token and refresh-session operations."""

    session: AsyncSessionT
    refresh_token_model: type[Any]
    refresh_max_age: timedelta
    token_bytes: int
    _token_hash_secret: bytes
    _refresh_token_repository_type: TokenRepositoryType
    consumed_refresh_token_digest_model: type[RefreshTokenConsumedDigest]

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

    @staticmethod
    def _refresh_session_from_row(row: _RefreshTokenRow) -> RefreshSession:
        """Build safe public refresh-session metadata from a persistence row.

        Returns:
            Refresh-session metadata without token storage details.
        """
        return RefreshSession(
            session_id=row.session_id,
            created_at=row.created_at,
            last_used_at=row.last_used_at,
            client_metadata=row.client_metadata,
        )

    async def list_refresh_sessions(self, user: UP) -> list[RefreshSession]:
        """Return active refresh sessions belonging to ``user``.

        Expired refresh-token rows are deleted before active sessions are returned.

        Returns:
            Active refresh-session metadata ordered by creation time.
        """
        expired_count = await self._delete_expired_refresh_sessions_for_user(user)
        if expired_count:
            await self.session.commit()

        result = await self.session.execute(
            select(self.refresh_token_model)
            .where(self.refresh_token_model.user_id == user.id)
            .order_by(self.refresh_token_model.created_at),
        )
        rows = cast("list[_RefreshTokenRow]", result.scalars().all())
        return [self._refresh_session_from_row(row) for row in rows]

    async def revoke_refresh_session(self, user: UP, session_id: str) -> bool:
        """Revoke one active refresh session for ``user`` by public session id.

        Returns:
            ``True`` when a matching active session was deleted, otherwise ``False``.
        """
        expired_count = await self._delete_expired_refresh_sessions_for_user(user)
        deleted_marker_count = await self._delete_refresh_session_consumed_digests(
            select(self.refresh_token_model.session_id).where(
                self.refresh_token_model.user_id == user.id,
                self.refresh_token_model.session_id == session_id,
            ),
        )
        deleted_count = await self._execute_delete(
            delete(self.refresh_token_model).where(
                self.refresh_token_model.user_id == user.id,
                self.refresh_token_model.session_id == session_id,
            ),
        )
        if expired_count or deleted_marker_count or deleted_count:
            await self.session.commit()
        return deleted_count > 0

    async def revoke_other_refresh_sessions(self, user: UP, current_session_id: str | None) -> int:
        """Revoke active refresh sessions for ``user`` except ``current_session_id``.

        Returns:
            Number of active refresh sessions revoked.
        """
        expired_count = await self._delete_expired_refresh_sessions_for_user(user)
        conditions = [self.refresh_token_model.user_id == user.id]
        if current_session_id is not None:
            conditions.append(self.refresh_token_model.session_id != current_session_id)
        deleted_marker_count = await self._delete_refresh_session_consumed_digests(
            select(self.refresh_token_model.session_id).where(*conditions),
        )
        deleted_count = await self._execute_delete(delete(self.refresh_token_model).where(*conditions))
        if expired_count or deleted_marker_count or deleted_count:
            await self.session.commit()
        return deleted_count

    async def identify_refresh_session(self, user: UP, refresh_token: str) -> str | None:
        """Return the public refresh-session id for ``refresh_token`` when it belongs to ``user``.

        Returns:
            Public refresh-session id, or ``None`` when the token is missing, expired, or not owned by ``user``.
        """
        persisted_token = cast(
            "_RefreshTokenRow | None",
            await self._resolve_token(
                self._repository(self._refresh_token_repository_type),
                refresh_token,
                load=[],
            ),
        )
        if persisted_token is None or persisted_token.user_id != user.id:
            token_digest = self._token_digest(refresh_token)
            compromised_row = await self._find_refresh_token_row_by_consumed_digest(token_digest)
            if compromised_row is not None and compromised_row.user_id == user.id:
                await self._revoke_refresh_session_chain(compromised_row.session_id)
                await self.session.commit()
            return None
        if self._is_token_expired(persisted_token.created_at, self.refresh_max_age):
            await self._delete_refresh_token_row(persisted_token)
            await self.session.commit()
            return None
        return persisted_token.session_id

    async def _load_refresh_session_row(self, user: UP, session_id: str) -> _RefreshTokenRow | None:
        """Return one refresh-token row by public session id for a user."""
        result = await self.session.execute(
            select(self.refresh_token_model).where(
                self.refresh_token_model.user_id == user.id,
                self.refresh_token_model.session_id == session_id,
            ),
        )
        return cast("_RefreshTokenRow | None", result.scalars().first())

    async def issue_totp_stepup(self, user: UP, session_id: str, *, ttl_seconds: int) -> None:
        """Store a short-lived TOTP step-up marker on a DB-backed refresh session."""
        row = await self._load_refresh_session_row(user, session_id)
        if row is None:
            return
        metadata = dict(row.client_metadata or {})
        if ttl_seconds <= 0:
            metadata.pop(_CLIENT_METADATA_TOTP_STEPUP_EXPIRES_AT_KEY, None)
        else:
            expires_at = datetime.now(tz=UTC).timestamp() + ttl_seconds
            metadata[_CLIENT_METADATA_TOTP_STEPUP_EXPIRES_AT_KEY] = str(expires_at)
        row.client_metadata = metadata or None
        await self.session.commit()

    async def has_recent_totp_verification(self, user: UP, session_id: str) -> bool:
        """Return whether a DB-backed refresh session has a live TOTP step-up marker."""
        row = await self._load_refresh_session_row(user, session_id)
        if row is None:
            return False
        metadata = row.client_metadata or {}
        try:
            expires_at = float(metadata.get(_CLIENT_METADATA_TOTP_STEPUP_EXPIRES_AT_KEY, ""))
        except ValueError:
            return False
        if expires_at > datetime.now(tz=UTC).timestamp():
            return True
        metadata = dict(metadata)
        metadata.pop(_CLIENT_METADATA_TOTP_STEPUP_EXPIRES_AT_KEY, None)
        row.client_metadata = metadata or None
        await self.session.commit()
        return False

    async def _delete_expired_refresh_sessions_for_user(self, user: UP) -> int:
        """Delete expired refresh-token rows for ``user``.

        Returns:
            Number of deleted rows.
        """
        cutoff = datetime.now(tz=UTC) - self.refresh_max_age
        await self._delete_refresh_session_consumed_digests(
            select(self.refresh_token_model.session_id).where(
                self.refresh_token_model.user_id == user.id,
                self.refresh_token_model.created_at <= cutoff,
            ),
        )
        return await self._execute_delete(
            delete(self.refresh_token_model).where(
                self.refresh_token_model.user_id == user.id,
                self.refresh_token_model.created_at <= cutoff,
            ),
        )

    async def _delete_refresh_session_consumed_digests(self, session_ids: Iterable[Any] | InElementRole) -> int:
        """Delete consumed-digest index rows for the selected refresh sessions.

        Returns:
            Number of consumed-digest rows deleted.
        """
        return await self._execute_delete(
            delete(self.consumed_refresh_token_digest_model).where(
                self.consumed_refresh_token_digest_model.session_id.in_(session_ids),
            ),
        )
