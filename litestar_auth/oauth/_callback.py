"""OAuth callback token exchange and provider identity resolution."""

from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING

from litestar_auth.exceptions import AuthenticationError

if TYPE_CHECKING:
    from litestar_auth.oauth._client import OAuthClientAdapter, OAuthTokenPayload


@dataclass(frozen=True, slots=True)
class OAuthCallbackIdentity:
    """Provider callback payload resolved from a token exchange."""

    account_id: str
    account_email: str
    email_verified: bool | None
    token_payload: OAuthTokenPayload


class OAuthCallbackResolver:
    """Resolve PKCE-bound provider callbacks into provider account identity."""

    def __init__(self, client: OAuthClientAdapter) -> None:
        """Bind the provider client adapter."""
        self._client = client

    async def resolve_login_callback(
        self,
        *,
        code: str,
        redirect_uri: str,
        code_verifier: str,
    ) -> OAuthCallbackIdentity:
        """Exchange a login callback code and return identity plus email-verification evidence.

        Returns:
            Provider account identity, verification signal, and token payload.
        """
        token_payload = await self._exchange_code(
            code=code,
            redirect_uri=redirect_uri,
            code_verifier=code_verifier,
        )
        (account_id, account_email), email_verified = await self._client.get_account_identity_and_email_verified(
            token_payload["access_token"],
        )
        return OAuthCallbackIdentity(
            account_id=account_id,
            account_email=account_email,
            email_verified=email_verified,
            token_payload=token_payload,
        )

    async def resolve_associate_callback(
        self,
        *,
        code: str,
        redirect_uri: str,
        code_verifier: str,
    ) -> OAuthCallbackIdentity:
        """Exchange an association callback code and return provider identity.

        Returns:
            Provider account identity and token payload. The email-verification field is unset because association is
            initiated by an already authenticated local user.
        """
        token_payload = await self._exchange_code(
            code=code,
            redirect_uri=redirect_uri,
            code_verifier=code_verifier,
        )
        account_id, account_email = await self._client.get_account_identity(token_payload["access_token"])
        return OAuthCallbackIdentity(
            account_id=account_id,
            account_email=account_email,
            email_verified=None,
            token_payload=token_payload,
        )

    async def _exchange_code(
        self,
        *,
        code: str,
        redirect_uri: str,
        code_verifier: str,
    ) -> OAuthTokenPayload:
        """Exchange a provider callback code after validating PKCE verifier material.

        Returns:
            Normalized provider token payload.
        """
        _require_code_verifier(code_verifier)
        return await self._client.get_access_token(
            code=code,
            redirect_uri=redirect_uri,
            code_verifier=code_verifier,
        )


def _require_code_verifier(code_verifier: str) -> None:
    """Require recoverable PKCE verifier material before token exchange.

    Raises:
        AuthenticationError: If the callback cannot provide a non-empty verifier.
    """
    if code_verifier.strip():
        return

    msg = "OAuth callback is missing PKCE code verifier."
    raise AuthenticationError(msg)
