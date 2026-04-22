"""OAuth flow orchestration services."""

from __future__ import annotations

import secrets
from dataclasses import dataclass
from typing import TYPE_CHECKING, Any, Protocol, runtime_checkable

from litestar.exceptions import ClientException

import litestar_auth._account_state as _shared_account_state
from litestar_auth.exceptions import (
    ConfigurationError,
    ErrorCode,
    InactiveUserError,
    OAuthAccountAlreadyLinkedError,
    UnverifiedUserError,
)
from litestar_auth.types import UserProtocol

if TYPE_CHECKING:
    from collections.abc import Mapping

    from litestar_auth.oauth.client_adapter import OAuthClientAdapter, OAuthTokenPayload


_ACCOUNT_STATE_ERROR_TYPES = _shared_account_state.AccountStateErrorTypes(
    inactive_error=InactiveUserError,
    unverified_error=UnverifiedUserError,
)
_resolve_account_state_validator = _shared_account_state.resolve_account_state_validator


class OAuthServiceUserStoreProtocol[UP: UserProtocol[Any], ID](Protocol):
    """User persistence operations required by OAuth flow orchestration."""

    async def get_by_email(self, email: str) -> UP | None:
        """Return a user by email address."""


class OAuthAccountStoreProtocol[UP: UserProtocol[Any], ID](Protocol):
    """OAuth-account persistence operations required by OAuth flow orchestration."""

    async def get_by_oauth_account(self, oauth_name: str, account_id: str) -> UP | None:
        """Return a user linked to the given provider account."""

    async def upsert_oauth_account(  # noqa: PLR0913
        self,
        user: UP,
        *,
        oauth_name: str,
        account_id: str,
        account_email: str,
        access_token: str,
        expires_at: int | None,
        refresh_token: str | None,
    ) -> None:
        """Create or update the linked OAuth account."""


@runtime_checkable
class OAuthServiceUserManagerProtocol[UP: UserProtocol[Any], ID](Protocol):
    """User-manager behavior required by OAuth service orchestration."""

    user_db: OAuthServiceUserStoreProtocol[UP, ID]
    oauth_account_store: OAuthAccountStoreProtocol[UP, ID] | None

    async def create(
        self,
        user_create: Mapping[str, Any],
        *,
        safe: bool = True,
        allow_privileged: bool = False,
    ) -> UP:
        """Create and return a new user."""

    async def update(self, user_update: Mapping[str, Any], user: UP) -> UP:
        """Persist and return updates for an existing user."""

    async def on_after_login(self, user: UP) -> None:
        """Run post-login side effects for a fully authenticated user."""

    def require_account_state(self, user: UP, *, require_verified: bool = False) -> None:
        """Validate active and optionally verified account state."""


@dataclass(frozen=True, slots=True)
class OAuthAuthorization:
    """Authorization URL plus the state value that must be persisted by transport."""

    authorization_url: str
    state: str


class OAuthService[UP: UserProtocol[Any], ID]:
    """Coordinate provider callback, user bootstrap, and account linking."""

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
        self._client = client
        self._associate_by_email = associate_by_email
        self._trust_provider_email_verified = trust_provider_email_verified

    async def authorize(self, *, redirect_uri: str, scopes: list[str] | None = None) -> OAuthAuthorization:
        """Generate a callback state and provider authorization URL.

        Returns:
            Authorization payload containing the generated state and provider URL.
        """
        state = secrets.token_urlsafe(32)
        authorization_url = await self._client.get_authorization_url(
            redirect_uri=redirect_uri,
            state=state,
            scopes=scopes,
        )
        return OAuthAuthorization(authorization_url=authorization_url, state=state)

    async def complete_login(
        self,
        *,
        code: str,
        redirect_uri: str,
        user_manager: OAuthServiceUserManagerProtocol[UP, ID],
    ) -> UP:
        """Resolve the callback into a local user and linked OAuth account.

        Returns:
            The resolved or newly created local user.
        """
        token_payload = await self._client.get_access_token(code=code, redirect_uri=redirect_uri)
        (account_id, account_email), email_verified = await self._client.get_account_identity_and_email_verified(
            token_payload["access_token"],
        )

        self._require_provider_verification_signal(email_verified=email_verified)

        oauth_account_store = _require_oauth_account_store(user_manager)
        user, existing_by_email = await self._resolve_candidate_user(
            user_manager=user_manager,
            oauth_account_store=oauth_account_store,
            account_id=account_id,
            account_email=account_email,
        )
        user = await self._materialize_or_validate_user(
            user_manager=user_manager,
            user=user,
            existing_by_email=existing_by_email,
            account_email=account_email,
            email_verified=email_verified,
        )
        _require_account_state(user, user_manager=user_manager)

        await self._upsert_account(
            oauth_account_store=oauth_account_store,
            user=user,
            account_id=account_id,
            account_email=account_email,
            token_payload=token_payload,
        )
        return user

    def _require_provider_verification_signal(self, *, email_verified: bool | None) -> None:
        """Require provider verification signal when strict mode is enabled.

        Raises:
            ConfigurationError: If strict verification mode is enabled without provider signal.
        """
        if not self._trust_provider_email_verified or email_verified is not None:
            return

        msg = (
            "trust_provider_email_verified=True requires the OAuth provider to assert email ownership at "
            "runtime (email_verified=True) via get_profile() or get_email_verified()."
        )
        raise ConfigurationError(msg)

    async def _resolve_candidate_user(
        self,
        *,
        user_manager: OAuthServiceUserManagerProtocol[UP, ID],
        oauth_account_store: OAuthAccountStoreProtocol[UP, ID],
        account_id: str,
        account_email: str,
    ) -> tuple[UP | None, UP | None]:
        """Resolve user candidate from linked account first, then by email.

        Returns:
            Candidate user and optional email match marker.
        """
        user = await oauth_account_store.get_by_oauth_account(self._provider_name, account_id)
        if user is not None:
            return user, None

        existing_by_email = await user_manager.user_db.get_by_email(account_email)
        return existing_by_email, existing_by_email

    async def _materialize_or_validate_user(
        self,
        *,
        user_manager: OAuthServiceUserManagerProtocol[UP, ID],
        user: UP | None,
        existing_by_email: UP | None,
        account_email: str,
        email_verified: bool | None,
    ) -> UP:
        """Create new user or enforce account-link policy for existing user.

        Returns:
            User resolved from provider account identity.
        """
        if user is None:
            return await self._create_user_from_oauth(
                user_manager=user_manager,
                account_email=account_email,
                email_verified=email_verified,
            )
        if existing_by_email is None:
            return user

        self._validate_existing_email_link_policy(email_verified=email_verified)
        return user

    async def _create_user_from_oauth(
        self,
        *,
        user_manager: OAuthServiceUserManagerProtocol[UP, ID],
        account_email: str,
        email_verified: bool | None,
    ) -> UP:
        """Create local user for a new OAuth identity.

        Returns:
            Newly created local user (optionally marked as verified).
        """
        _require_verified_email_evidence(email_verified=email_verified)
        user = await user_manager.create(
            {
                "email": account_email,
                "password": secrets.token_urlsafe(32),
            },
            safe=True,
        )
        if self._trust_provider_email_verified and email_verified is True:
            return await user_manager.update({"is_verified": True}, user)
        return user

    def _validate_existing_email_link_policy(self, *, email_verified: bool | None) -> None:
        """Validate linking rules when provider email already exists locally.

        Raises:
            ClientException: If linking policy forbids association for current configuration.
        """
        if self._associate_by_email and not self._trust_provider_email_verified:
            msg = (
                "Cannot link account by email without provider email verification. "
                "Set trust_provider_email_verified=True only for providers that guarantee email ownership."
            )
            raise ClientException(
                status_code=400,
                detail=msg,
                extra={"code": ErrorCode.OAUTH_USER_ALREADY_EXISTS},
            )
        if self._associate_by_email and self._trust_provider_email_verified and email_verified is not True:
            _raise_email_not_verified()
        if not self._associate_by_email:
            msg = "A user with this email already exists. Sign in with your password or link this provider from your account."
            raise ClientException(
                status_code=400,
                detail=msg,
                extra={"code": ErrorCode.OAUTH_USER_ALREADY_EXISTS},
            )

    async def associate_account(
        self,
        *,
        user: UP,
        code: str,
        redirect_uri: str,
        user_manager: OAuthServiceUserManagerProtocol[UP, ID],
    ) -> None:
        """Link a provider account to an already authenticated user."""
        token_payload = await self._client.get_access_token(code=code, redirect_uri=redirect_uri)
        account_id, account_email = await self._client.get_account_identity(token_payload["access_token"])
        oauth_account_store = _require_oauth_account_store(user_manager)
        existing_owner = await oauth_account_store.get_by_oauth_account(self._provider_name, account_id)
        if existing_owner is not None:
            existing_owner_id = getattr(existing_owner, "id", None)
            current_user_id = getattr(user, "id", None)
            if existing_owner_id is None or current_user_id is None or existing_owner_id != current_user_id:
                _raise_account_already_linked()
        await self._upsert_account(
            oauth_account_store=oauth_account_store,
            user=user,
            account_id=account_id,
            account_email=account_email,
            token_payload=token_payload,
        )

    async def _upsert_account(
        self,
        *,
        oauth_account_store: OAuthAccountStoreProtocol[UP, ID],
        user: UP,
        account_id: str,
        account_email: str,
        token_payload: OAuthTokenPayload,
    ) -> None:
        """Persist or update the linked OAuth account for a local user."""
        try:
            await oauth_account_store.upsert_oauth_account(
                user,
                oauth_name=self._provider_name,
                account_id=account_id,
                account_email=account_email,
                access_token=token_payload["access_token"],
                expires_at=token_payload["expires_at"],
                refresh_token=token_payload["refresh_token"],
            )
        except OAuthAccountAlreadyLinkedError:
            _raise_account_already_linked()


def _require_oauth_account_store[UP: UserProtocol[Any], ID](
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


def _require_account_state(
    user: object,
    *,
    user_manager: object,
) -> None:
    """Validate the user account state and map failures to client-facing errors."""
    _shared_account_state.require_account_state_with_client_error(
        user,
        require_verified=False,
        prioritize_unverified=False,
        user_manager=user_manager,
        error_types=_ACCOUNT_STATE_ERROR_TYPES,
    )


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


def _raise_email_not_verified() -> None:
    """Raise the stable provider-email verification error.

    Raises:
        ClientException: Always raised with the OAuth email-not-verified error payload.
    """
    msg = "Provider email is not verified."
    raise ClientException(
        status_code=400,
        detail=msg,
        extra={"code": ErrorCode.OAUTH_EMAIL_NOT_VERIFIED},
    )


def _require_verified_email_evidence(*, email_verified: bool | None) -> None:
    """Require explicit provider-verified email evidence for new-account OAuth sign-in."""
    if email_verified is True:
        return

    _raise_email_not_verified()
