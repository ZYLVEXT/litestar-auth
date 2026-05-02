"""Internal helpers for generated OAuth controllers."""

from __future__ import annotations

import hmac
from dataclasses import dataclass
from ipaddress import ip_address
from typing import TYPE_CHECKING, Any, NoReturn
from urllib.parse import urlsplit

from litestar.exceptions import ClientException

from litestar_auth.exceptions import ConfigurationError, ErrorCode
from litestar_auth.oauth.service import (
    _require_verified_email_evidence as _service_require_verified_email_evidence,
)

if TYPE_CHECKING:
    from collections.abc import Sequence

    from litestar import Request
    from litestar.response import Response

    from litestar_auth.oauth._flow_cookie import _OAuthFlowCookie, _OAuthFlowCookieCipher

STATE_COOKIE_MAX_AGE = 300


@dataclass(frozen=True, slots=True)
class _OAuthCookieSettings:
    """Provider-scoped OAuth flow-cookie settings."""

    cookie_name: str
    cookie_path: str
    cookie_secure: bool
    flow_cookie_cipher: _OAuthFlowCookieCipher


def _build_callback_url_from_base(redirect_base_url: str, provider_name: str) -> str:
    """Return the absolute callback URL for the authorize/callback pair.

    Returns:
        redirect_base_url with trailing slash stripped, plus /{provider_name}/callback.
    """
    return f"{redirect_base_url.rstrip('/')}/{provider_name}/callback"


def _validate_manual_oauth_redirect_base_url(redirect_base_url: str) -> None:
    """Validate the fail-closed redirect-origin contract for manual OAuth controllers.

    Raises:
        ConfigurationError: If the redirect base does not use a non-loopback public
            HTTPS origin or includes unsupported URL components.
    """
    parsed_redirect_base_url = urlsplit(redirect_base_url)
    if parsed_redirect_base_url.scheme.casefold() != "https":
        msg = (
            "Manual/custom OAuth controllers require redirect_base_url to use a public HTTPS origin. "
            f"Received {redirect_base_url!r}."
        )
        raise ConfigurationError(msg)

    host = parsed_redirect_base_url.hostname
    if host is None or _is_loopback_host(host):
        msg = (
            "Manual/custom OAuth controllers require redirect_base_url to use a non-loopback public HTTPS origin. "
            f"Received {redirect_base_url!r}."
        )
        raise ConfigurationError(msg)
    if (
        parsed_redirect_base_url.username is not None
        or parsed_redirect_base_url.password is not None
        or parsed_redirect_base_url.query
        or parsed_redirect_base_url.fragment
    ):
        msg = (
            "Manual/custom OAuth controllers require redirect_base_url to be a clean HTTPS callback base without "
            "userinfo, query, or fragment components. "
            f"Received {redirect_base_url!r}."
        )
        raise ConfigurationError(msg)


def _is_loopback_host(host: str) -> bool:
    """Return whether ``host`` is a localhost or loopback IP literal."""
    if host.casefold() == "localhost":
        return True
    try:
        return ip_address(host).is_loopback
    except ValueError:
        return False


def _normalize_oauth_scopes(scopes: Sequence[str] | None) -> tuple[str, ...] | None:
    """Return normalized server-owned OAuth scopes, or ``None`` when unset.

    Raises:
        ConfigurationError: If any configured scope is empty or contains whitespace.
    """
    if scopes is None:
        return None

    normalized_scopes: list[str] = []
    seen_scopes: set[str] = set()
    for raw_scope in scopes:
        if not isinstance(raw_scope, str):
            msg = "OAuth scopes must be strings."
            raise ConfigurationError(msg)
        scope = raw_scope.strip()
        if not scope:
            msg = "OAuth scopes must be non-empty strings."
            raise ConfigurationError(msg)
        if any(character.isspace() for character in scope):
            msg = "OAuth scopes must be provided as individual tokens without embedded whitespace."
            raise ConfigurationError(msg)
        if scope not in seen_scopes:
            normalized_scopes.append(scope)
            seen_scopes.add(scope)

    return tuple(normalized_scopes) if normalized_scopes else None


def _reject_runtime_oauth_scope_override(request: Request[Any, Any, Any]) -> None:
    """Reject caller-controlled scope overrides on OAuth authorize endpoints.

    Raises:
        ClientException: If the request attempts to override OAuth scopes.
    """
    query_params = getattr(request, "query_params", None)
    if query_params is None or query_params.get("scopes") is None:
        return

    msg = "OAuth scopes must be configured on the server."
    raise ClientException(status_code=400, detail=msg)


def _build_cookie_path(*, path: str, provider_name: str) -> str:
    """Return the cookie path for a provider-specific OAuth controller.

    Returns:
        Provider-specific cookie path used for OAuth state cookies.
    """
    return f"{path.rstrip('/')}/{provider_name}"


def _set_state_cookie(
    response: Response[Any],
    *,
    flow_cookie: _OAuthFlowCookie,
    cookie_settings: _OAuthCookieSettings,
) -> None:
    """Store encrypted OAuth state and PKCE verifier material in the provider-scoped cookie."""
    response.set_cookie(
        key=cookie_settings.cookie_name,
        value=_encode_oauth_flow_cookie(flow_cookie, flow_cookie_cipher=cookie_settings.flow_cookie_cipher),
        max_age=STATE_COOKIE_MAX_AGE,
        path=cookie_settings.cookie_path,
        secure=cookie_settings.cookie_secure,
        httponly=True,
        samesite="lax",
    )


def _clear_state_cookie(
    response: Response[Any],
    *,
    cookie_name: str,
    cookie_path: str,
    cookie_secure: bool,
) -> None:
    """Expire the provider-scoped OAuth state cookie."""
    response.set_cookie(
        key=cookie_name,
        value="",
        max_age=0,
        path=cookie_path,
        secure=cookie_secure,
        httponly=True,
        samesite="lax",
    )


def _encode_oauth_flow_cookie(
    flow_cookie: _OAuthFlowCookie,
    *,
    flow_cookie_cipher: _OAuthFlowCookieCipher,
) -> str:
    """Return a versioned encrypted envelope for OAuth flow material."""
    return flow_cookie_cipher.encrypt(flow_cookie)


def _decode_oauth_flow_cookie(
    cookie_value: str | None,
    *,
    flow_cookie_cipher: _OAuthFlowCookieCipher,
) -> _OAuthFlowCookie:
    """Decrypt OAuth flow material from the state cookie.

    Returns:
        Decoded OAuth state and PKCE verifier.
    """
    return flow_cookie_cipher.decrypt(cookie_value)


def _validate_state(cookie_state: str | None, query_state: str) -> None:
    """Validate the callback ``state`` against the secure cookie value."""
    # Security: reject empty values before constant-time comparison to prevent
    # trivial empty-string matching (hmac.compare_digest("", "") == True).
    if not cookie_state or not query_state or not hmac.compare_digest(cookie_state, query_state):
        _raise_invalid_oauth_state()


def _raise_invalid_oauth_state() -> NoReturn:
    """Raise the stable invalid OAuth state response.

    Raises:
        ClientException: Always raised with the public invalid-state response shape.
    """
    msg = "Invalid OAuth state."
    raise ClientException(status_code=400, detail=msg, extra={"code": ErrorCode.OAUTH_STATE_INVALID})


def _require_verified_email_evidence(*, email_verified: bool | None) -> None:
    """Require explicit provider-verified email evidence for new-account OAuth sign-in."""
    _service_require_verified_email_evidence(email_verified=email_verified)
