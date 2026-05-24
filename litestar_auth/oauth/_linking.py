"""OAuth account-linking policy and user materialization."""

from __future__ import annotations

import secrets
from typing import TYPE_CHECKING, Any

from litestar.exceptions import ClientException

from litestar_auth.exceptions import ConfigurationError, ErrorCode
from litestar_auth.types import UserProtocol

if TYPE_CHECKING:
    from litestar_auth.oauth._contracts import OAuthAccountStoreProtocol, OAuthServiceUserManagerProtocol


class OAuthLinkingPolicy:
    """Validate OAuth email-linking policy and create users for new identities."""

    def __init__(
        self,
        *,
        associate_by_email: bool = False,
        trust_provider_email_verified: bool = False,
    ) -> None:
        """Bind provider email-linking configuration."""
        self._associate_by_email = associate_by_email
        self._trust_provider_email_verified = trust_provider_email_verified

    def require_provider_verification_signal(self, *, email_verified: bool | None) -> None:
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

    @staticmethod
    async def resolve_candidate_user[UP: UserProtocol[Any], ID](
        *,
        provider_name: str,
        user_manager: OAuthServiceUserManagerProtocol[UP, ID],
        oauth_account_store: OAuthAccountStoreProtocol[UP, ID],
        account_id: str,
        account_email: str,
    ) -> tuple[UP | None, UP | None]:
        """Resolve user candidate from linked account first, then by email.

        Returns:
            Candidate user and optional email match marker.
        """
        user = await oauth_account_store.get_by_oauth_account(provider_name, account_id)
        if user is not None:
            return user, None

        existing_by_email = await user_manager.user_db.get_by_email(account_email)
        return existing_by_email, existing_by_email

    async def materialize_or_validate_user[UP: UserProtocol[Any], ID](
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
            return await self.create_user_from_oauth(
                user_manager=user_manager,
                account_email=account_email,
                email_verified=email_verified,
            )
        if existing_by_email is None:
            return user

        self.validate_existing_email_link_policy(email_verified=email_verified)
        return user

    async def create_user_from_oauth[UP: UserProtocol[Any], ID](
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
        require_verified_email_evidence(email_verified=email_verified)
        user = await user_manager.create(
            {
                "email": account_email,
                "password": secrets.token_urlsafe(32),
            },
            safe=True,
        )
        if self._trust_provider_email_verified and email_verified is True:
            return await user_manager.update({"is_verified": True}, user, allow_privileged=True)
        return user

    def validate_existing_email_link_policy(self, *, email_verified: bool | None) -> None:
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


def require_verified_email_evidence(*, email_verified: bool | None) -> None:
    """Require explicit provider-verified email evidence for new-account OAuth sign-in."""
    if email_verified is True:
        return

    _raise_email_not_verified()
