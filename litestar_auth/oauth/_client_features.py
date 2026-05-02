"""Feature detection helpers for OAuth client adapter contracts."""

from __future__ import annotations

import inspect
from typing import TYPE_CHECKING, TypeGuard

from litestar_auth.exceptions import ConfigurationError

if TYPE_CHECKING:
    from litestar_auth.oauth._client_contracts import (
        OAuthAccessTokenClientProtocol,
        OAuthAuthorizationURLClientProtocol,
        OAuthDirectIdentityClientProtocol,
        OAuthEmailVerificationAsyncClientProtocol,
        OAuthProfileClientProtocol,
    )


def _supports_authorization_url(oauth_client: object) -> TypeGuard[OAuthAuthorizationURLClientProtocol]:
    """Return whether the client exposes ``get_authorization_url()``."""
    return callable(getattr(oauth_client, "get_authorization_url", None))


def _supports_access_token(oauth_client: object) -> TypeGuard[OAuthAccessTokenClientProtocol]:
    """Return whether the client exposes ``get_access_token()``."""
    return callable(getattr(oauth_client, "get_access_token", None))


def _is_httpx_oauth_client(oauth_client: object) -> bool:
    """Return whether the client comes from the optional httpx-oauth package."""
    return type(oauth_client).__module__.startswith("httpx_oauth.")


def _supports_direct_identity(oauth_client: object) -> TypeGuard[OAuthDirectIdentityClientProtocol]:
    """Return whether the client exposes ``get_id_email()``."""
    return callable(getattr(oauth_client, "get_id_email", None))


def _supports_profile(oauth_client: object) -> TypeGuard[OAuthProfileClientProtocol]:
    """Return whether the client exposes ``get_profile()``."""
    return callable(getattr(oauth_client, "get_profile", None))


def _validate_oauth_method_accepts_keywords(
    method: object,
    *,
    method_name: str,
    keyword_names: tuple[str, ...],
) -> None:
    """Validate that an OAuth client method can receive required PKCE kwargs.

    Raises:
        ConfigurationError: If the method is not callable or omits required PKCE kwargs.
    """
    if not callable(method):
        msg = f"OAuth client {method_name} must be callable when provided."
        raise ConfigurationError(msg)

    signature = inspect.signature(method)
    if any(parameter.kind is inspect.Parameter.VAR_KEYWORD for parameter in signature.parameters.values()):
        return

    missing_keywords = [
        keyword_name for keyword_name in keyword_names if not _signature_accepts_keyword(signature, keyword_name)
    ]
    if not missing_keywords:
        return

    missing = ", ".join(missing_keywords)
    msg = f"OAuth client {method_name} must support PKCE keyword argument(s): {missing}."
    raise ConfigurationError(msg)


def _signature_accepts_keyword(signature: inspect.Signature, keyword_name: str) -> bool:
    """Return whether a signature accepts the named keyword argument."""
    parameter = signature.parameters.get(keyword_name)
    return parameter is not None and parameter.kind in {
        inspect.Parameter.POSITIONAL_OR_KEYWORD,
        inspect.Parameter.KEYWORD_ONLY,
    }


def _validate_email_verified_result(result: object) -> bool:
    """Return a valid provider email-verification result.

    Raises:
        ConfigurationError: If the result is not a bool.
    """
    if isinstance(result, bool):
        return result
    msg = "OAuth client returned an invalid email verification value."
    raise ConfigurationError(msg)


def _supports_async_email_verified(oauth_client: object) -> TypeGuard[OAuthEmailVerificationAsyncClientProtocol]:
    """Return whether the client exposes the async verification contract."""
    email_verification_method = getattr(oauth_client, "get_email_verified", None)
    if not callable(email_verification_method):
        return False
    code = getattr(email_verification_method, "__code__", None)
    return code is not None and bool(code.co_flags & inspect.CO_COROUTINE)


def _supports_email_verified(
    oauth_client: object,
) -> TypeGuard[OAuthEmailVerificationAsyncClientProtocol]:
    """Return whether the client exposes the async verification contract."""
    return _supports_async_email_verified(oauth_client)
