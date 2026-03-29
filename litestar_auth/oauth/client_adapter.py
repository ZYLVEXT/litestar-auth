"""Adapter for normalizing third-party OAuth client contracts."""

from __future__ import annotations

import inspect
from collections.abc import Callable, Mapping
from typing import Any, TypedDict

from litestar.exceptions import ClientException

from litestar_auth.exceptions import ConfigurationError, ErrorCode

ACCOUNT_IDENTITY_LENGTH = 2


class OAuthTokenPayload(TypedDict):
    """Normalized OAuth access-token payload."""

    access_token: str
    expires_at: int | None
    refresh_token: str | None


class OAuthClientAdapter:
    """Wrap a provider client behind a normalized async interface."""

    def __init__(self, oauth_client: object) -> None:
        """Bind the raw OAuth client implementation."""
        self._oauth_client = oauth_client

    async def get_authorization_url(
        self,
        *,
        redirect_uri: str,
        state: str,
        scopes: list[str] | None = None,
    ) -> str:
        """Return the provider authorization URL for the given callback state.

        Returns:
            Absolute provider authorization URL.

        Raises:
            ConfigurationError: If the client does not expose a valid authorization-url contract.
        """
        get_authorization_url = getattr(self._oauth_client, "get_authorization_url", None)
        if get_authorization_url is None:
            msg = "OAuth client must define get_authorization_url()."
            raise ConfigurationError(msg)

        if scopes:
            scope_str = " ".join(scopes)
            authorization_url = await get_authorization_url(
                redirect_uri,
                state,
                scope=scope_str,
            )
        else:
            authorization_url = await get_authorization_url(redirect_uri, state)
        if not isinstance(authorization_url, str) or not authorization_url:
            msg = "OAuth client returned an invalid authorization URL."
            raise ConfigurationError(msg)
        return authorization_url

    async def get_access_token(self, *, code: str, redirect_uri: str) -> OAuthTokenPayload:
        """Exchange the provider callback code for an OAuth access token.

        Returns:
            Normalized access-token payload with `access_token`, `expires_at`, and `refresh_token`.

        Raises:
            ConfigurationError: If the client does not expose a valid token-exchange contract.
        """
        get_access_token = getattr(self._oauth_client, "get_access_token", None)
        if get_access_token is None:
            msg = "OAuth client must define get_access_token()."
            raise ConfigurationError(msg)

        raw_payload = await get_access_token(code, redirect_uri)
        payload = _as_mapping(raw_payload, message="OAuth client returned an invalid access-token payload.")
        access_token = payload.get("access_token")
        expires_at = payload.get("expires_at")
        refresh_token = payload.get("refresh_token")
        if not isinstance(access_token, str) or not access_token:
            msg = "OAuth client access-token payload must include a non-empty access_token."
            raise ConfigurationError(msg)
        if expires_at is not None and not isinstance(expires_at, int):
            msg = "OAuth client access-token payload returned an invalid expires_at value."
            raise ConfigurationError(msg)
        if refresh_token is not None and not isinstance(refresh_token, str):
            msg = "OAuth client access-token payload returned an invalid refresh_token value."
            raise ConfigurationError(msg)
        return {
            "access_token": access_token,
            "expires_at": expires_at,
            "refresh_token": refresh_token,
        }

    async def get_account_identity(self, access_token: str) -> tuple[str, str]:
        """Return the upstream account identifier and email for the access token.

        Returns:
            Tuple containing the provider account id and email address.
        """
        identity = await self._get_identity_from_direct_contract(access_token)
        if identity is not None:
            return identity
        return await self._get_identity_from_profile(access_token)

    async def _get_identity_from_direct_contract(self, access_token: str) -> tuple[str, str] | None:
        """Return identity from ``get_id_email`` when provider exposes it.

        Returns:
            `(account_id, account_email)` when contract is available, otherwise ``None``.

        Raises:
            ConfigurationError: If provider returned malformed identity payload.
        """
        get_id_email = getattr(self._oauth_client, "get_id_email", None)
        if get_id_email is None:
            return None

        account_identity = await get_id_email(access_token)
        if account_identity is None:
            return None
        parsed_identity = _as_account_identity_tuple(account_identity)
        if parsed_identity is not None:
            return parsed_identity

        msg = "OAuth client returned an invalid account identity."
        raise ConfigurationError(msg)

    async def _get_identity_from_profile(self, access_token: str) -> tuple[str, str]:
        """Return identity from profile payload fallback.

        Returns:
            Tuple containing provider account id and email.

        Raises:
            ConfigurationError: If profile contract is missing or malformed.
        """
        get_profile = getattr(self._oauth_client, "get_profile", None)
        if get_profile is None:
            msg = "OAuth client must define get_id_email() or get_profile()."
            raise ConfigurationError(msg)

        raw_profile = await get_profile(access_token)
        profile = _as_mapping(raw_profile, message="OAuth client returned an invalid profile payload.")
        return _extract_identity_from_profile(profile)

    async def get_email_verified(self, access_token: str) -> bool | None:
        """Return a provider asserted email-verification signal for the access token."""
        get_email_verified = getattr(self._oauth_client, "get_email_verified", None)
        if get_email_verified is not None:
            return await self._call_dedicated_email_verified(get_email_verified, access_token)

        get_profile = getattr(self._oauth_client, "get_profile", None)
        if get_profile is None:
            return None

        raw_profile = await get_profile(access_token)
        profile = _as_mapping(raw_profile, message="OAuth client returned an invalid profile payload.")
        return _parse_email_verified_from_profile(profile)

    async def get_account_identity_and_email_verified(
        self,
        access_token: str,
    ) -> tuple[tuple[str, str], bool | None]:
        """Return identity and email-verification signal in a single profile fetch.

        When the provider lacks ``get_id_email``, both identity and
        ``email_verified`` are extracted from a single ``get_profile()``
        call, eliminating the TOCTOU window that arises from two separate
        HTTP requests.

        Returns:
            Tuple of ``(account_id, account_email)`` and ``email_verified``.

        Raises:
            ConfigurationError: If the client does not expose a valid identity or
                email-verification contract.
        """
        identity = await self._get_identity_from_direct_contract(access_token)
        if identity is not None:
            email_verified = await self.get_email_verified(access_token)
            return identity, email_verified

        get_profile = getattr(self._oauth_client, "get_profile", None)
        if get_profile is None:
            msg = "OAuth client must define get_id_email() or get_profile()."
            raise ConfigurationError(msg)

        raw_profile = await get_profile(access_token)
        profile = _as_mapping(raw_profile, message="OAuth client returned an invalid profile payload.")
        identity = _extract_identity_from_profile(profile)

        get_email_verified_fn = getattr(self._oauth_client, "get_email_verified", None)
        if get_email_verified_fn is not None:
            email_verified = await self._call_dedicated_email_verified(get_email_verified_fn, access_token)
        else:
            email_verified = _parse_email_verified_from_profile(profile)

        return identity, email_verified

    @staticmethod
    async def _call_dedicated_email_verified(
        get_email_verified: Callable[..., Any],
        access_token: str,
    ) -> bool:
        """Invoke the provider's dedicated ``get_email_verified`` contract.

        Returns:
            Provider-asserted email-verification boolean.

        Raises:
            ConfigurationError: If the return value is not a bool.
        """
        maybe_awaitable = get_email_verified(access_token)
        result = await maybe_awaitable if inspect.isawaitable(maybe_awaitable) else maybe_awaitable
        if isinstance(result, bool):
            return result
        msg = "OAuth client returned an invalid email verification value."
        raise ConfigurationError(msg)


def _parse_email_verified_from_profile(profile: Mapping[str, object]) -> bool | None:
    """Parse the ``email_verified`` field from a provider profile mapping.

    Returns:
        ``True``/``False`` when present and parseable, ``None`` when absent.

    Raises:
        ConfigurationError: If the value is present but unparseable.
    """
    email_verified = profile.get("email_verified")
    if email_verified is None:
        return None
    if isinstance(email_verified, bool):
        return email_verified
    if isinstance(email_verified, str):
        lowered = email_verified.strip().lower()
        if lowered in {"true", "false"}:
            return lowered == "true"
    msg = "OAuth provider returned an invalid email_verified value."
    raise ConfigurationError(msg)


def _as_mapping(raw_payload: object, *, message: str) -> Mapping[str, object]:
    """Normalize an arbitrary payload object into a mapping.

    Returns:
        Mapping view over the payload.

    Raises:
        ConfigurationError: If the payload cannot be normalized into a mapping.
    """
    if isinstance(raw_payload, Mapping):
        return {str(key): value for key, value in raw_payload.items()}
    if hasattr(raw_payload, "__dict__"):
        return {str(k): v for k, v in vars(raw_payload).items()}

    raise ConfigurationError(message)


def _as_account_identity_tuple(account_identity: object) -> tuple[str, str] | None:
    """Return ``(account_id, email)`` when the provider payload matches the contract."""
    if not (isinstance(account_identity, tuple) and len(account_identity) == ACCOUNT_IDENTITY_LENGTH):
        return None
    account_id, account_email = account_identity
    if isinstance(account_id, str) and isinstance(account_email, str) and bool(account_id) and bool(account_email):
        return account_id, account_email
    return None


def _extract_identity_from_profile(profile: Mapping[str, object]) -> tuple[str, str]:
    """Extract account identity fields from profile payload.

    Returns:
        Tuple containing provider account id and email.

    Raises:
        ConfigurationError: If profile omits account id.
        ClientException: If profile omits email required for sign-in.
    """
    account_id = profile.get("account_id", profile.get("id"))
    account_email = profile.get("account_email", profile.get("email"))
    if not isinstance(account_id, str) or not account_id:
        msg = "OAuth profile payload must include a non-empty account id."
        raise ConfigurationError(msg)
    if not isinstance(account_email, str) or not account_email:
        msg = "OAuth provider did not return an email. Please use a different sign-in method."
        raise ClientException(
            status_code=400,
            detail=msg,
            extra={"code": ErrorCode.OAUTH_NOT_AVAILABLE_EMAIL},
        )
    return account_id, account_email
