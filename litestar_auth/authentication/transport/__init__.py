"""Move opaque human sessions through HTTP cookies with an HttpOnly default.

Transports are composed with a :class:`~litestar_auth.authentication.strategy.Strategy`
inside an :class:`~litestar_auth.authentication.backend.AuthenticationBackend`.
"""

from litestar_auth.authentication.transport.base import Transport
from litestar_auth.authentication.transport.cookie import CookieTransport, CookieTransportConfig

__all__ = ["CookieTransport", "CookieTransportConfig", "Transport"]
