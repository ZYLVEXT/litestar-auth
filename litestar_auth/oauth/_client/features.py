"""Feature detection and payload helpers for OAuth client adapters."""

from __future__ import annotations

import inspect
from collections.abc import Mapping
from typing import TypeGuard

from litestar.exceptions import ClientException

from litestar_auth.exceptions import ConfigurationError, ErrorCode
from litestar_auth.oauth._client.protocol import (
    ACCOUNT_IDENTITY_LENGTH,
    OAuthAccessTokenClientProtocol,
    OAuthAuthorizationURLClientProtocol,
    OAuthDirectIdentityClientProtocol,
    OAuthEmailVerificationAsyncClientProtocol,
    OAuthProfileClientProtocol,
)


def supports_authorization_url(oauth_client: object) -> TypeGuard[OAuthAuthorizationURLClientProtocol]:
    """Return whether the client exposes ``get_authorization_url()``."""
    return callable(getattr(oauth_client, "get_authorization_url", None))


def supports_access_token(oauth_client: object) -> TypeGuard[OAuthAccessTokenClientProtocol]:
    """Return whether the client exposes ``get_access_token()``."""
    return callable(getattr(oauth_client, "get_access_token", None))


def is_httpx_oauth_client(oauth_client: object) -> bool:
    """Return whether the client comes from the optional httpx-oauth package."""
    return type(oauth_client).__module__.startswith("httpx_oauth.")


def supports_direct_identity(oauth_client: object) -> TypeGuard[OAuthDirectIdentityClientProtocol]:
    """Return whether the client exposes ``get_id_email()``."""
    return callable(getattr(oauth_client, "get_id_email", None))


def supports_profile(oauth_client: object) -> TypeGuard[OAuthProfileClientProtocol]:
    """Return whether the client exposes ``get_profile()``."""
    return callable(getattr(oauth_client, "get_profile", None))


def validate_oauth_method_accepts_keywords(
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


def validate_email_verified_result(result: object) -> bool:
    """Return a valid provider email-verification result.

    Raises:
        ConfigurationError: If the result is not a bool.
    """
    if isinstance(result, bool):
        return result
    msg = "OAuth client returned an invalid email verification value."
    raise ConfigurationError(msg)


def supports_async_email_verified(oauth_client: object) -> TypeGuard[OAuthEmailVerificationAsyncClientProtocol]:
    """Return whether the client exposes the async verification contract."""
    email_verification_method = getattr(oauth_client, "get_email_verified", None)
    if not callable(email_verification_method):
        return False
    code = getattr(email_verification_method, "__code__", None)
    return code is not None and bool(code.co_flags & inspect.CO_COROUTINE)


def supports_email_verified(
    oauth_client: object,
) -> TypeGuard[OAuthEmailVerificationAsyncClientProtocol]:
    """Return whether the client exposes the async verification contract."""
    return supports_async_email_verified(oauth_client)


def validate_oauth_client_adapter_fields(oauth_client: object) -> None:
    """Validate advertised manual OAuth client fields at adapter construction.

    Raises:
        ConfigurationError: If an advertised adapter field is malformed.
    """
    profile_method = getattr(oauth_client, "get_profile", None)
    if profile_method is not None and not callable(profile_method):
        msg = "OAuth client get_profile must be callable when provided."
        raise ConfigurationError(msg)

    email_verification_method = getattr(oauth_client, "get_email_verified", None)
    if email_verification_method is not None and not supports_email_verified(oauth_client):
        msg = (
            "OAuth client get_email_verified must be an async callable implementing "
            "OAuthEmailVerificationAsyncClientProtocol, or wrap sync clients with "
            "make_async_email_verification_client()."
        )
        raise ConfigurationError(msg)

    authorization_url_method = getattr(oauth_client, "get_authorization_url", None)
    if authorization_url_method is not None:
        validate_oauth_method_accepts_keywords(
            authorization_url_method,
            method_name="get_authorization_url",
            keyword_names=("code_challenge", "code_challenge_method"),
        )

    access_token_method = getattr(oauth_client, "get_access_token", None)
    if access_token_method is not None:
        validate_oauth_method_accepts_keywords(
            access_token_method,
            method_name="get_access_token",
            keyword_names=("code_verifier",),
        )


def parse_email_verified_from_profile(profile: Mapping[str, object]) -> bool | None:
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


def identity_and_email_verified_from_profile(profile: Mapping[str, object]) -> tuple[tuple[str, str], bool | None]:
    """Extract account identity and email-verification signal from one profile payload.

    Returns:
        Tuple of account identity and profile-derived email-verification signal.
    """
    return extract_identity_from_profile(profile), parse_email_verified_from_profile(profile)


def as_mapping(raw_payload: object, *, message: str) -> Mapping[str, object]:
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


def as_account_identity_tuple(account_identity: object) -> tuple[str, str] | None:
    """Return ``(account_id, email)`` when the provider payload matches the contract."""
    if not (isinstance(account_identity, tuple) and len(account_identity) == ACCOUNT_IDENTITY_LENGTH):
        return None
    account_id, account_email = account_identity
    if isinstance(account_id, str) and isinstance(account_email, str) and bool(account_id) and bool(account_email):
        return account_id, account_email
    return None


def extract_identity_from_profile(profile: Mapping[str, object]) -> tuple[str, str]:
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


def _signature_accepts_keyword(signature: inspect.Signature, keyword_name: str) -> bool:
    """Return whether a signature accepts the named keyword argument."""
    parameter = signature.parameters.get(keyword_name)
    return parameter is not None and parameter.kind in {
        inspect.Parameter.POSITIONAL_OR_KEYWORD,
        inspect.Parameter.KEYWORD_ONLY,
    }
