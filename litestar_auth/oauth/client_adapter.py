"""Adapter for normalizing third-party OAuth client contracts.

OAuth authorization-code clients must support PKCE S256 per RFC 7636: authorization URLs receive
``code_challenge`` and ``code_challenge_method="S256"``, and callback token exchanges receive the matching
``code_verifier``. The adapter validates that manual clients expose those keyword arguments instead of silently
downgrading the flow.
"""

from __future__ import annotations

import asyncio
from collections.abc import Mapping
from typing import Literal

from litestar.exceptions import ClientException

from litestar_auth.exceptions import ConfigurationError, ErrorCode
from litestar_auth.oauth._client_contracts import (
    ACCOUNT_IDENTITY_LENGTH,
    OAuthAccessTokenClientProtocol,
    OAuthAuthorizationURLClientProtocol,
    OAuthClientClassLoader,
    OAuthClientConstructor,
    OAuthClientFactory,
    OAuthClientProtocol,
    OAuthDirectIdentityClientProtocol,
    OAuthEmailVerificationAsyncClientProtocol,
    OAuthEmailVerificationSyncClientProtocol,
    OAuthPayloadObjectProtocol,
    OAuthPayloadSource,
    OAuthProfileClientProtocol,
    OAuthTokenPayload,
)
from litestar_auth.oauth._client_features import (
    _is_httpx_oauth_client,
    _supports_access_token,
    _supports_async_email_verified,  # noqa: F401
    _supports_authorization_url,
    _supports_direct_identity,
    _supports_email_verified,
    _supports_profile,
    _validate_email_verified_result,
    _validate_oauth_method_accepts_keywords,
)

__all__ = (
    "OAuthAccessTokenClientProtocol",
    "OAuthAuthorizationURLClientProtocol",
    "OAuthClientAdapter",
    "OAuthClientClassLoader",
    "OAuthClientConstructor",
    "OAuthClientFactory",
    "OAuthClientProtocol",
    "OAuthDirectIdentityClientProtocol",
    "OAuthEmailVerificationAsyncClientProtocol",
    "OAuthEmailVerificationSyncClientProtocol",
    "OAuthPayloadObjectProtocol",
    "OAuthPayloadSource",
    "OAuthProfileClientProtocol",
    "OAuthTokenPayload",
    "_build_oauth_client_adapter",
    "make_async_email_verification_client",
)


class _AsyncEmailVerificationClientAdapter:
    """Wrap a blocking sync verification client behind an async interface."""

    def __init__(self, sync_client: OAuthEmailVerificationSyncClientProtocol) -> None:
        """Bind the sync verification client to offload in a worker thread."""
        self._sync_client = sync_client

    async def get_email_verified(self, access_token: str) -> bool:
        """Return provider verification evidence without blocking the event loop.

        This wrapper is only appropriate for truly blocking sync clients.
        Prefer a native async client for fast in-memory checks.

        Returns:
            Provider-asserted email-verification boolean.

        Raises:
            ConfigurationError: If the sync client returns a non-bool value.
        """
        result = await asyncio.to_thread(self._sync_client.get_email_verified, access_token)
        if isinstance(result, bool):
            return result
        msg = "OAuth client returned an invalid email verification value."
        raise ConfigurationError(msg)


def make_async_email_verification_client(
    sync_client: OAuthEmailVerificationSyncClientProtocol,
) -> OAuthEmailVerificationAsyncClientProtocol:
    """Wrap a sync verification client behind an async thread-offloaded adapter.

    Use this only for truly blocking sync clients. For cheap in-memory checks,
    implement :class:`OAuthEmailVerificationAsyncClientProtocol` directly.

    Returns:
        Async adapter that runs the sync client in a worker thread.
    """
    return _AsyncEmailVerificationClientAdapter(sync_client)


def _resolve_oauth_client(
    *,
    oauth_client: OAuthClientProtocol | None = None,
    oauth_client_factory: OAuthClientFactory | None = None,
    oauth_client_class: str | None = None,
    oauth_client_kwargs: Mapping[str, object] | None = None,
    oauth_client_class_loader: OAuthClientClassLoader | None = None,
) -> OAuthClientProtocol:
    """Resolve the supported manual OAuth client provisioning contract.

    Returns:
        Concrete OAuth client instance resolved from the supported provisioning inputs.

    Raises:
        ConfigurationError: If no client configuration is provided.
    """
    client = oauth_client
    if client is None and oauth_client_factory is not None:
        client = oauth_client_factory()
    if client is None and oauth_client_class is not None:
        if oauth_client_class_loader is None:
            msg = "oauth_client_class requires an OAuth client loader."
            raise ConfigurationError(msg)
        client = oauth_client_class_loader(
            oauth_client_class,
            **dict(oauth_client_kwargs or {}),
        )
    if client is None:
        msg = "Provide oauth_client, oauth_client_factory, or oauth_client_class."
        raise ConfigurationError(msg)
    return client


def _build_oauth_client_adapter(
    *,
    oauth_client: OAuthClientProtocol | None = None,
    oauth_client_factory: OAuthClientFactory | None = None,
    oauth_client_class: str | None = None,
    oauth_client_kwargs: Mapping[str, object] | None = None,
    oauth_client_class_loader: OAuthClientClassLoader | None = None,
) -> OAuthClientAdapter:
    """Resolve and wrap a manual OAuth client behind the normalized adapter.

    Returns:
        Normalized adapter bound to the resolved manual OAuth client.
    """
    return OAuthClientAdapter(
        _resolve_oauth_client(
            oauth_client=oauth_client,
            oauth_client_factory=oauth_client_factory,
            oauth_client_class=oauth_client_class,
            oauth_client_kwargs=oauth_client_kwargs,
            oauth_client_class_loader=oauth_client_class_loader,
        ),
    )


def _validate_oauth_client_adapter_fields(oauth_client: object) -> None:
    """Validate advertised manual OAuth client fields at adapter construction.

    Raises:
        ConfigurationError: If an advertised adapter field is malformed.
    """
    profile_method = getattr(oauth_client, "get_profile", None)
    if profile_method is not None and not callable(profile_method):
        msg = "OAuth client get_profile must be callable when provided."
        raise ConfigurationError(msg)

    email_verification_method = getattr(oauth_client, "get_email_verified", None)
    if email_verification_method is not None and not _supports_email_verified(oauth_client):
        msg = (
            "OAuth client get_email_verified must be an async callable implementing "
            "OAuthEmailVerificationAsyncClientProtocol, or wrap sync clients with "
            "make_async_email_verification_client()."
        )
        raise ConfigurationError(msg)

    authorization_url_method = getattr(oauth_client, "get_authorization_url", None)
    if authorization_url_method is not None:
        _validate_oauth_method_accepts_keywords(
            authorization_url_method,
            method_name="get_authorization_url",
            keyword_names=("code_challenge", "code_challenge_method"),
        )

    access_token_method = getattr(oauth_client, "get_access_token", None)
    if access_token_method is not None:
        _validate_oauth_method_accepts_keywords(
            access_token_method,
            method_name="get_access_token",
            keyword_names=("code_verifier",),
        )


class OAuthClientAdapter:
    """Wrap a provider client behind a normalized async interface.

    The adapter preserves the RFC 7636 PKCE S256 contract by forwarding authorization
    ``code_challenge`` values and token-exchange ``code_verifier`` values to the wrapped client.
    """

    def __init__(self, oauth_client: OAuthClientProtocol) -> None:
        """Bind the raw OAuth client implementation."""
        _validate_oauth_client_adapter_fields(oauth_client)
        self._oauth_client = oauth_client

    async def get_authorization_url(
        self,
        *,
        redirect_uri: str,
        state: str,
        scopes: list[str] | None = None,
        code_challenge: str | None = None,
        code_challenge_method: Literal["S256"] | None = None,
    ) -> str:
        """Return the provider authorization URL for the given callback state and PKCE challenge.

        Returns:
            Absolute provider authorization URL containing the provider-specific RFC 7636 challenge parameters.

        Raises:
            ConfigurationError: If the client does not expose a valid authorization-url contract.
        """
        if not _supports_authorization_url(self._oauth_client):
            msg = "OAuth client must define get_authorization_url()."
            raise ConfigurationError(msg)

        scope: str | list[str] | None = None
        if scopes:
            scope = scopes if _is_httpx_oauth_client(self._oauth_client) else " ".join(scopes)
        authorization_url = await self._oauth_client.get_authorization_url(
            redirect_uri,
            state,
            scope=scope,
            code_challenge=code_challenge,
            code_challenge_method=code_challenge_method,
        )
        if not isinstance(authorization_url, str) or not authorization_url:
            msg = "OAuth client returned an invalid authorization URL."
            raise ConfigurationError(msg)
        return authorization_url

    async def get_access_token(
        self,
        *,
        code: str,
        redirect_uri: str,
        code_verifier: str | None = None,
    ) -> OAuthTokenPayload:
        """Exchange the provider callback code and PKCE verifier for an OAuth access token.

        Returns:
            Normalized access-token payload with `access_token`, `expires_at`, and `refresh_token`.

        Raises:
            ConfigurationError: If the client does not expose a valid token-exchange contract.
        """
        if not _supports_access_token(self._oauth_client):
            msg = "OAuth client must define get_access_token()."
            raise ConfigurationError(msg)

        raw_payload = await self._oauth_client.get_access_token(code, redirect_uri, code_verifier=code_verifier)
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
        if not _supports_direct_identity(self._oauth_client):
            return None

        account_identity = await self._oauth_client.get_id_email(access_token)
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
        if not _supports_profile(self._oauth_client):
            msg = "OAuth client must define get_id_email() or get_profile()."
            raise ConfigurationError(msg)

        raw_profile = await self._oauth_client.get_profile(access_token)
        profile = _as_mapping(raw_profile, message="OAuth client returned an invalid profile payload.")
        return _extract_identity_from_profile(profile)

    async def get_email_verified(self, access_token: str) -> bool | None:
        """Return a provider asserted email-verification signal for the access token."""
        if _supports_email_verified(self._oauth_client):
            return await self._call_dedicated_email_verified(self._oauth_client, access_token)

        if not _supports_profile(self._oauth_client):
            return None

        raw_profile = await self._oauth_client.get_profile(access_token)
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

        if not _supports_profile(self._oauth_client):
            msg = "OAuth client must define get_id_email() or get_profile()."
            raise ConfigurationError(msg)

        raw_profile = await self._oauth_client.get_profile(access_token)
        profile = _as_mapping(raw_profile, message="OAuth client returned an invalid profile payload.")
        identity = _extract_identity_from_profile(profile)

        if _supports_email_verified(self._oauth_client):
            email_verified = await self._call_dedicated_email_verified(self._oauth_client, access_token)
        else:
            email_verified = _parse_email_verified_from_profile(profile)

        return identity, email_verified

    @staticmethod
    async def _call_dedicated_email_verified(
        oauth_client: OAuthEmailVerificationAsyncClientProtocol,
        access_token: str,
    ) -> bool:
        """Invoke the async ``get_email_verified`` contract.

        Returns:
            Provider-asserted email-verification boolean.
        """
        return _validate_email_verified_result(await oauth_client.get_email_verified(access_token))


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
