"""Adapter for normalizing third-party OAuth client contracts.

OAuth authorization-code clients must support PKCE S256 per RFC 7636: authorization URLs receive
``code_challenge`` and ``code_challenge_method="S256"``, and callback token exchanges receive the matching
``code_verifier``. The adapter validates that manual clients expose those keyword arguments instead of silently
downgrading the flow.
"""

from __future__ import annotations

import asyncio
from typing import TYPE_CHECKING, Literal

from litestar_auth.exceptions import ConfigurationError
from litestar_auth.oauth._client import features

if TYPE_CHECKING:
    from collections.abc import Mapping

    from litestar_auth.oauth._client.protocol import (
        OAuthClientClassLoader,
        OAuthClientFactory,
        OAuthClientProtocol,
        OAuthEmailVerificationAsyncClientProtocol,
        OAuthEmailVerificationSyncClientProtocol,
        OAuthTokenPayload,
    )

__all__ = (
    "OAuthClientAdapter",
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

        """
        result = await asyncio.to_thread(self._sync_client.get_email_verified, access_token)
        return features.validate_email_verified_result(result)


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


class OAuthClientAdapter:
    """Wrap a provider client behind a normalized async interface."""

    def __init__(self, oauth_client: OAuthClientProtocol) -> None:
        """Bind the raw OAuth client implementation."""
        features.validate_oauth_client_adapter_fields(oauth_client)
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

        Raises:
            ConfigurationError: If the provider method is missing or returns an invalid URL.
        """
        if not features.supports_authorization_url(self._oauth_client):
            msg = "OAuth client must define get_authorization_url()."
            raise ConfigurationError(msg)

        scope: str | list[str] | None = None
        if scopes:
            scope = scopes if features.is_httpx_oauth_client(self._oauth_client) else " ".join(scopes)
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
            Normalized provider access-token payload.

        Raises:
            ConfigurationError: If the provider method is missing or returns an invalid payload.
        """
        if not features.supports_access_token(self._oauth_client):
            msg = "OAuth client must define get_access_token()."
            raise ConfigurationError(msg)

        raw_payload = await self._oauth_client.get_access_token(code, redirect_uri, code_verifier=code_verifier)
        payload = features.as_mapping(raw_payload, message="OAuth client returned an invalid access-token payload.")
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
        """Return the upstream account identifier and email for the access token."""
        identity = await self._get_identity_from_direct_contract(access_token)
        if identity is not None:
            return identity
        return await self._get_identity_from_profile(access_token)

    async def _get_identity_from_direct_contract(self, access_token: str) -> tuple[str, str] | None:
        """Return identity from ``get_id_email`` when provider exposes it.

        Raises:
            ConfigurationError: If the provider returns malformed identity.
        """
        if not features.supports_direct_identity(self._oauth_client):
            return None

        account_identity = await self._oauth_client.get_id_email(access_token)
        if account_identity is None:
            return None
        parsed_identity = features.as_account_identity_tuple(account_identity)
        if parsed_identity is not None:
            return parsed_identity

        msg = "OAuth client returned an invalid account identity."
        raise ConfigurationError(msg)

    async def _get_identity_from_profile(self, access_token: str) -> tuple[str, str]:
        """Return identity from profile payload fallback.

        Raises:
            ConfigurationError: If the profile contract is missing or malformed.
        """
        if not features.supports_profile(self._oauth_client):
            msg = "OAuth client must define get_id_email() or get_profile()."
            raise ConfigurationError(msg)

        raw_profile = await self._oauth_client.get_profile(access_token)
        profile = features.as_mapping(raw_profile, message="OAuth client returned an invalid profile payload.")
        return features.extract_identity_from_profile(profile)

    async def get_email_verified(self, access_token: str) -> bool | None:
        """Return a provider asserted email-verification signal for the access token."""
        if features.supports_email_verified(self._oauth_client):
            return await self._call_dedicated_email_verified(self._oauth_client, access_token)

        if not features.supports_profile(self._oauth_client):
            return None

        raw_profile = await self._oauth_client.get_profile(access_token)
        profile = features.as_mapping(raw_profile, message="OAuth client returned an invalid profile payload.")
        return features.parse_email_verified_from_profile(profile)

    async def get_account_identity_and_email_verified(
        self,
        access_token: str,
    ) -> tuple[tuple[str, str], bool | None]:
        """Return identity and email-verification signal in a single profile fetch.

        Raises:
            ConfigurationError: If the client cannot provide a valid identity.
        """
        identity = await self._get_identity_from_direct_contract(access_token)
        if identity is not None:
            email_verified = await self.get_email_verified(access_token)
            return identity, email_verified

        if not features.supports_profile(self._oauth_client):
            msg = "OAuth client must define get_id_email() or get_profile()."
            raise ConfigurationError(msg)

        raw_profile = await self._oauth_client.get_profile(access_token)
        profile = features.as_mapping(raw_profile, message="OAuth client returned an invalid profile payload.")
        return features.identity_and_email_verified_from_profile(profile)

    @staticmethod
    async def _call_dedicated_email_verified(
        oauth_client: OAuthEmailVerificationAsyncClientProtocol,
        access_token: str,
    ) -> bool:
        return features.validate_email_verified_result(await oauth_client.get_email_verified(access_token))
