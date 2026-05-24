"""OAuth flow orchestration services.

Authorization-code flows generate and require PKCE S256 material per RFC 7636. Each authorize call creates a
fresh ``code_verifier`` and ``code_challenge``; each callback must present the matching verifier before the
provider token exchange proceeds.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

from litestar_auth.oauth._account_state import require_account_state
from litestar_auth.oauth._accounts import OAuthAccountUpserter, require_oauth_account_store
from litestar_auth.oauth._authorization import OAuthAuthorization, OAuthAuthorizationIssuer
from litestar_auth.oauth._callback import OAuthCallbackResolver
from litestar_auth.oauth._contracts import (
    OAuthAccountStoreProtocol,
    OAuthServiceUserManagerProtocol,
    OAuthServiceUserStoreProtocol,
)
from litestar_auth.oauth._linking import OAuthLinkingPolicy
from litestar_auth.types import UserProtocol

if TYPE_CHECKING:
    from litestar_auth.oauth._client import OAuthClientAdapter

__all__ = (
    "OAuthAccountStoreProtocol",
    "OAuthAuthorization",
    "OAuthService",
    "OAuthServiceUserManagerProtocol",
    "OAuthServiceUserStoreProtocol",
)


class OAuthService[UP: UserProtocol[Any], ID]:
    """Coordinate PKCE-bound provider callbacks, user bootstrap, and account linking."""

    def __init__(
        self,
        *,
        provider_name: str,
        client: OAuthClientAdapter,
        associate_by_email: bool = False,
        trust_provider_email_verified: bool = False,
    ) -> None:
        """Bind provider-specific OAuth orchestration dependencies."""
        self._provider_name = provider_name
        self._authorization_issuer = OAuthAuthorizationIssuer(client)
        self._callback_resolver = OAuthCallbackResolver(client)
        self._linking_policy = OAuthLinkingPolicy(
            associate_by_email=associate_by_email,
            trust_provider_email_verified=trust_provider_email_verified,
        )

    async def authorize(self, *, redirect_uri: str, scopes: list[str] | None = None) -> OAuthAuthorization:
        """Generate callback state, RFC 7636 PKCE S256 material, and provider authorization URL.

        Returns:
            Authorization payload containing the generated state, provider URL, and PKCE verifier to persist.
        """
        return await self._authorization_issuer.authorize(redirect_uri=redirect_uri, scopes=scopes)

    async def complete_login(
        self,
        *,
        code: str,
        redirect_uri: str,
        code_verifier: str,
        user_manager: OAuthServiceUserManagerProtocol[UP, ID],
    ) -> UP:
        """Resolve a PKCE-bound callback into a local user and linked OAuth account.

        The ``code_verifier`` is required and forwarded to the provider token endpoint, matching the
        RFC 7636 challenge generated during authorization.

        Returns:
            The resolved or newly created local user.
        """
        callback_identity = await self._callback_resolver.resolve_login_callback(
            code=code,
            redirect_uri=redirect_uri,
            code_verifier=code_verifier,
        )
        self._linking_policy.require_provider_verification_signal(
            email_verified=callback_identity.email_verified,
        )

        oauth_account_store = require_oauth_account_store(user_manager)
        account_upserter = OAuthAccountUpserter(
            provider_name=self._provider_name,
            oauth_account_store=oauth_account_store,
        )
        user, existing_by_email = await self._linking_policy.resolve_candidate_user(
            provider_name=self._provider_name,
            user_manager=user_manager,
            oauth_account_store=oauth_account_store,
            account_id=callback_identity.account_id,
            account_email=callback_identity.account_email,
        )
        user = await self._linking_policy.materialize_or_validate_user(
            user_manager=user_manager,
            user=user,
            existing_by_email=existing_by_email,
            account_email=callback_identity.account_email,
            email_verified=callback_identity.email_verified,
        )
        require_account_state(user, user_manager=user_manager)

        await account_upserter.upsert_account(
            user=user,
            account_id=callback_identity.account_id,
            account_email=callback_identity.account_email,
            token_payload=callback_identity.token_payload,
        )
        return user

    async def associate_account(
        self,
        *,
        user: UP,
        code: str,
        redirect_uri: str,
        code_verifier: str,
        user_manager: OAuthServiceUserManagerProtocol[UP, ID],
    ) -> None:
        """Link a provider account to an authenticated user after PKCE-bound token exchange."""
        callback_identity = await self._callback_resolver.resolve_associate_callback(
            code=code,
            redirect_uri=redirect_uri,
            code_verifier=code_verifier,
        )
        oauth_account_store = require_oauth_account_store(user_manager)
        account_upserter = OAuthAccountUpserter(
            provider_name=self._provider_name,
            oauth_account_store=oauth_account_store,
        )
        await account_upserter.reject_cross_user_association(user=user, account_id=callback_identity.account_id)
        await account_upserter.upsert_account(
            user=user,
            account_id=callback_identity.account_id,
            account_email=callback_identity.account_email,
            token_payload=callback_identity.token_payload,
        )
