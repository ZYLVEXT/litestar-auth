"""Private OAuth client adapter package."""

from __future__ import annotations

from litestar_auth.oauth._client.adapter import (
    OAuthClientAdapter,
    _build_oauth_client_adapter,
    make_async_email_verification_client,
)
from litestar_auth.oauth._client.protocol import (
    ACCOUNT_IDENTITY_LENGTH,
    OAuthAccessTokenClientProtocol,
    OAuthAuthorizationURLClientProtocol,
    OAuthClientBaseProtocol,
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

__all__ = (
    "ACCOUNT_IDENTITY_LENGTH",
    "OAuthAccessTokenClientProtocol",
    "OAuthAuthorizationURLClientProtocol",
    "OAuthClientAdapter",
    "OAuthClientBaseProtocol",
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
