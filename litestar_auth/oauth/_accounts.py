"""OAuth account-store interactions."""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

from litestar.exceptions import ClientException

from litestar_auth.db import OAuthAccountData
from litestar_auth.exceptions import ErrorCode, OAuthAccountAlreadyLinkedError
from litestar_auth.types import UserProtocol

if TYPE_CHECKING:
    from litestar_auth.oauth._client import OAuthTokenPayload
    from litestar_auth.oauth._contracts import OAuthAccountStoreProtocol, OAuthServiceUserManagerProtocol


class OAuthAccountUpserter[UP: UserProtocol[Any], ID]:
    """Persist provider account links and validate association ownership."""

    def __init__(
        self,
        *,
        provider_name: str,
        oauth_account_store: OAuthAccountStoreProtocol[UP, ID],
    ) -> None:
        """Bind provider-specific store dependencies."""
        self._provider_name = provider_name
        self._oauth_account_store = oauth_account_store

    async def reject_cross_user_association(self, *, user: UP, account_id: str) -> None:
        """Reject association when the provider account already belongs to another local user."""
        existing_owner = await self._oauth_account_store.get_by_oauth_account(self._provider_name, account_id)
        if existing_owner is None:
            return

        existing_owner_id = getattr(existing_owner, "id", None)
        current_user_id = getattr(user, "id", None)
        if existing_owner_id is None or current_user_id is None or existing_owner_id != current_user_id:
            _raise_account_already_linked()

    async def upsert_account(
        self,
        *,
        user: UP,
        account_id: str,
        account_email: str,
        token_payload: OAuthTokenPayload,
    ) -> None:
        """Persist or update the linked OAuth account for a local user."""
        try:
            await self._oauth_account_store.upsert_oauth_account(
                user,
                account=OAuthAccountData(
                    oauth_name=self._provider_name,
                    account_id=account_id,
                    account_email=account_email,
                    access_token=token_payload["access_token"],
                    expires_at=token_payload["expires_at"],
                    refresh_token=token_payload["refresh_token"],
                ),
            )
        except OAuthAccountAlreadyLinkedError:
            _raise_account_already_linked()


def require_oauth_account_store[UP: UserProtocol[Any], ID](
    user_manager: OAuthServiceUserManagerProtocol[UP, ID],
) -> OAuthAccountStoreProtocol[UP, ID]:
    """Return the configured OAuth-account store or fail with a clear contract error.

    Raises:
        TypeError: If the manager does not expose an explicit OAuth-account store.
    """
    oauth_account_store = user_manager.oauth_account_store
    if oauth_account_store is not None:
        return oauth_account_store

    msg = "OAuth flows require a manager configured with an explicit oauth_account_store."
    raise TypeError(msg)


def _raise_account_already_linked() -> None:
    """Raise the stable linked-account client error.

    Raises:
        ClientException: Always raised with the OAuth linked-account error payload.
    """
    msg = (
        "This provider account is already linked to another user. "
        "One provider identity can only be linked to a single local account."
    )
    raise ClientException(
        status_code=400,
        detail=msg,
        extra={"code": ErrorCode.OAUTH_ACCOUNT_ALREADY_LINKED},
    ) from None
