"""Refresh-token request metadata helpers."""

from __future__ import annotations

_CLIENT_METADATA_USER_AGENT_KEY = "user_agent"
_CLIENT_METADATA_TOTP_STEPUP_EXPIRES_AT_KEY = "totp_stepup_expires_at"
_MAX_CLIENT_METADATA_VALUE_LENGTH = 255


class _DatabaseRefreshTokenMetadataMixin:
    """Capture bounded request metadata for database refresh sessions."""

    _refresh_token_request_metadata: dict[str, str] | None

    @staticmethod
    def _bounded_client_metadata_value(value: object) -> str | None:
        """Return a normalized, bounded metadata value safe for refresh-session storage."""
        if not isinstance(value, str):
            return None
        normalized = " ".join(value.split())
        if not normalized:
            return None
        return normalized[:_MAX_CLIENT_METADATA_VALUE_LENGTH]

    @classmethod
    def _extract_refresh_token_client_metadata(cls, request: object) -> dict[str, str] | None:
        """Return bounded client metadata derived from the current HTTP request."""
        headers = getattr(request, "headers", {})
        user_agent = cls._bounded_client_metadata_value(getattr(headers, "get", lambda _: None)("user-agent"))
        if user_agent is None:
            return None
        return {_CLIENT_METADATA_USER_AGENT_KEY: user_agent}

    def set_refresh_token_request_context(self, request: object) -> None:
        """Capture safe request metadata for the next refresh-token write or rotation."""
        self._refresh_token_request_metadata = self._extract_refresh_token_client_metadata(request)

    def _consume_refresh_token_request_metadata(self) -> dict[str, str] | None:
        """Return captured request metadata and clear it from the strategy instance."""
        metadata = self._refresh_token_request_metadata
        self._refresh_token_request_metadata = None
        return metadata
