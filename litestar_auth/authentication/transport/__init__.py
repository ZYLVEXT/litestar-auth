"""Move credentials between client and server (Bearer header vs HTTP-only cookies).

Transports are composed with a :class:`~litestar_auth.authentication.strategy.Strategy`
inside an :class:`~litestar_auth.authentication.backend.AuthenticationBackend`.
"""

from litestar_auth.authentication.transport.base import Transport
from litestar_auth.authentication.transport.bearer import BearerTransport
from litestar_auth.authentication.transport.cookie import CookieTransport, CookieTransportConfig

__all__ = ["BearerTransport", "CookieTransport", "CookieTransportConfig", "Transport"]
