"""Public-key resolver protocol and static onboarding documents."""

from __future__ import annotations

from typing import Protocol

from authweave_webhooks.models import PublicKeyDocument


class PublicKeyResolver(Protocol):
    """Resolve and optionally refresh the trusted public-key document."""

    async def resolve(self) -> PublicKeyDocument:
        """Return the currently trusted key document.

        Returns:
            The onboarding-trusted public-key document.
        """
        ...

    async def refresh(self) -> PublicKeyDocument | None:
        """Perform at most one controlled refresh when verification misses.

        Returns:
            The latest trusted document, or ``None`` when refresh is
            unavailable. Concurrent callers may receive a document refreshed by
            another caller without performing a second remote refresh.
        """
        ...


class StaticPublicKeyResolver:
    """In-memory resolver for tests and single-document onboarding fixtures."""

    __slots__ = ("_document", "_refresh_document", "_refreshed")

    def __init__(
        self,
        document: PublicKeyDocument,
        *,
        refresh_document: PublicKeyDocument | None = None,
    ) -> None:
        """Bind the active document and an optional one-shot refresh document."""
        self._document = document
        self._refresh_document = refresh_document
        self._refreshed = False

    async def resolve(self) -> PublicKeyDocument:
        """Return the current document.

        Returns:
            The trusted public-key document.
        """
        return self._document

    async def refresh(self) -> PublicKeyDocument | None:
        """Replace the document once from the configured refresh snapshot.

        Returns:
            The refreshed/current document, or ``None`` when no refresh snapshot
            is configured. Only the first caller changes the snapshot; later
            concurrent callers receive the same refreshed document.
        """
        if self._refreshed:
            return self._document
        if self._refresh_document is None:
            return None
        self._refreshed = True
        self._document = self._refresh_document
        return self._document
