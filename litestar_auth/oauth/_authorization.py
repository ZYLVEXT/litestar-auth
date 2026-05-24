"""OAuth authorization URL issuance."""

from __future__ import annotations

import secrets
from dataclasses import dataclass
from typing import TYPE_CHECKING

from litestar_auth.oauth._pkce import _generate_pkce_material

if TYPE_CHECKING:
    from litestar_auth.oauth._client import OAuthClientAdapter


@dataclass(frozen=True, slots=True)
class OAuthAuthorization:
    """Authorization URL plus state and PKCE verifier material persisted by transport."""

    authorization_url: str
    state: str
    code_verifier: str


class OAuthAuthorizationIssuer:
    """Issue provider authorization URLs with fresh state and PKCE material."""

    def __init__(self, client: OAuthClientAdapter) -> None:
        """Bind the provider client adapter."""
        self._client = client

    async def authorize(self, *, redirect_uri: str, scopes: list[str] | None = None) -> OAuthAuthorization:
        """Generate callback state, RFC 7636 PKCE S256 material, and provider authorization URL.

        Returns:
            Authorization payload containing the generated state, provider URL, and PKCE verifier to persist.
        """
        state = secrets.token_urlsafe(32)
        pkce = _generate_pkce_material()
        authorization_url = await self._client.get_authorization_url(
            redirect_uri=redirect_uri,
            state=state,
            scopes=scopes,
            code_challenge=pkce.code_challenge,
            code_challenge_method=pkce.code_challenge_method,
        )
        return OAuthAuthorization(
            authorization_url=authorization_url,
            state=state,
            code_verifier=pkce.code_verifier,
        )
