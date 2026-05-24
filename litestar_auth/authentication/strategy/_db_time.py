"""Timestamp helpers for database token strategies."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta


class _DatabaseTokenTimeMixin:
    """Shared timestamp normalization for persisted token rows."""

    @staticmethod
    def _normalize_timestamp(value: datetime) -> datetime:
        """Normalize persisted timestamps to UTC-aware datetimes.

        Returns:
            UTC-aware timestamp.
        """
        if value.tzinfo is None:
            return value.replace(tzinfo=UTC)
        return value.astimezone(UTC)

    def _is_token_expired(self, created_at: datetime, max_age: timedelta) -> bool:  # pragma: no cover
        """Return whether a token created at ``created_at`` exceeds ``max_age``."""
        normalized = self._normalize_timestamp(created_at)
        expires_at = normalized + max_age
        return expires_at <= datetime.now(tz=UTC)
