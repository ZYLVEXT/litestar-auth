"""Typed contracts for manual OAuth clients."""

from __future__ import annotations

from collections.abc import Callable, Mapping
from typing import Literal, Protocol, TypedDict, runtime_checkable

ACCOUNT_IDENTITY_LENGTH = 2  # pragma: no cover


class OAuthPayloadObjectProtocol(Protocol):  # pragma: no cover
    """Attribute-based payload object supported by the manual OAuth helpers."""

    __dict__: dict[str, object]


type OAuthPayloadSource = Mapping[str, object] | OAuthPayloadObjectProtocol  # pragma: no cover


class OAuthAuthorizationURLClientProtocol(Protocol):  # pragma: no cover
    """Manual OAuth client contract for RFC 7636 authorization URL resolution."""

    async def get_authorization_url(
        self,
        redirect_uri: str,
        state: str,
        *,
        scope: str | list[str] | None = None,
        code_challenge: str | None = None,
        code_challenge_method: Literal["S256"] | None = None,
    ) -> str:
        """Return the upstream provider authorization URL with optional PKCE S256 challenge material."""


class OAuthAccessTokenClientProtocol(Protocol):  # pragma: no cover
    """Manual OAuth client contract for RFC 7636 callback token exchange."""

    async def get_access_token(
        self,
        code: str,
        redirect_uri: str,
        *,
        code_verifier: str | None = None,
    ) -> OAuthPayloadSource:
        """Exchange a callback code and optional PKCE verifier for a token payload."""


class OAuthClientBaseProtocol(
    OAuthAuthorizationURLClientProtocol,
    OAuthAccessTokenClientProtocol,
    Protocol,
):  # pragma: no cover
    """Base manual OAuth client contract used by login and associate flows."""


class OAuthDirectIdentityClientProtocol(OAuthClientBaseProtocol, Protocol):  # pragma: no cover
    """Manual OAuth client contract with direct identity resolution.

    Returning ``None`` requests the documented ``get_profile()`` fallback.
    """

    async def get_id_email(self, access_token: str) -> tuple[str, str] | None:
        """Return provider account id and email, or ``None`` for profile fallback."""


class OAuthProfileClientProtocol(OAuthClientBaseProtocol, Protocol):  # pragma: no cover
    """Manual OAuth client contract with profile-based identity resolution."""

    async def get_profile(self, access_token: str) -> OAuthPayloadSource:
        """Return the upstream profile payload."""


@runtime_checkable
class OAuthEmailVerificationAsyncClientProtocol(Protocol):  # pragma: no cover
    """Async-only manual OAuth client contract for email verification evidence."""

    async def get_email_verified(self, access_token: str) -> bool:
        """Return provider email-verification evidence."""


class OAuthEmailVerificationSyncClientProtocol(Protocol):  # pragma: no cover
    """Sync-only manual OAuth client contract for email verification evidence."""

    def get_email_verified(self, access_token: str) -> bool:
        """Return provider email-verification evidence."""


type OAuthClientProtocol = OAuthDirectIdentityClientProtocol | OAuthProfileClientProtocol  # pragma: no cover
type OAuthClientFactory = Callable[[], OAuthClientProtocol]  # pragma: no cover
type OAuthClientConstructor = Callable[..., OAuthClientProtocol]  # pragma: no cover


class OAuthClientClassLoader(Protocol):  # pragma: no cover
    """Lazy loader contract for fully qualified manual OAuth client class paths."""

    def __call__(self, oauth_client_class: str, /, **client_kwargs: object) -> OAuthClientProtocol:
        """Load and instantiate a configured manual OAuth client."""


class OAuthTokenPayload(TypedDict):  # pragma: no cover
    """Normalized OAuth access-token payload."""

    access_token: str
    expires_at: int | None
    refresh_token: str | None
