"""Runtime cookie transport and CSRF helpers for plugin middleware setup."""

from __future__ import annotations

from typing import TYPE_CHECKING, Any, cast

from litestar.config.csrf import CSRFConfig

from litestar_auth._plugin.config import DEFAULT_CSRF_COOKIE_NAME, LitestarAuthConfig
from litestar_auth.authentication.transport.cookie import CookieTransport
from litestar_auth.types import UserProtocol

if TYPE_CHECKING:
    from collections.abc import Sequence

    from litestar_auth.authentication.backend import AuthenticationBackend


def get_cookie_transports[UP: UserProtocol[Any], ID](
    backends: Sequence[AuthenticationBackend[UP, ID]],
) -> list[CookieTransport]:
    """Return configured cookie transports from the backend list."""
    return [
        transport
        for backend in backends
        if isinstance((transport := getattr(backend, "transport", None)), CookieTransport)
    ]


def build_csrf_config[UP: UserProtocol[Any], ID](
    config: LitestarAuthConfig[UP, ID],
    cookie_transports: Sequence[CookieTransport],
) -> CSRFConfig:
    """Build a shared CSRF configuration for homogeneous cookie transports.

    Returns:
        CSRF settings derived from the shared cookie transport configuration.

    Raises:
        ValueError: If cookie transport settings are not homogeneous.
    """
    reference_transport = cookie_transports[0]
    for transport in cookie_transports[1:]:
        if (
            transport.path != reference_transport.path
            or transport.domain != reference_transport.domain
            or transport.secure != reference_transport.secure
            or transport.samesite != reference_transport.samesite
        ):
            msg = (
                "All CookieTransport backends must share path, domain, secure, and samesite settings "
                "to use the plugin-managed CSRF configuration."
            )
            raise ValueError(msg)

    return CSRFConfig(
        secret=cast("str", config.csrf_secret),
        cookie_name=DEFAULT_CSRF_COOKIE_NAME,
        cookie_path=reference_transport.path,
        header_name=config.csrf_header_name,
        cookie_secure=reference_transport.secure,
        cookie_samesite=reference_transport.samesite,
        cookie_domain=reference_transport.domain,
    )
