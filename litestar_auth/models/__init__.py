"""ORM models package.

Import :mod:`litestar_auth.models.oauth` when you need :class:`~litestar_auth.models.oauth.OAuthAccount`
without registering the library :class:`~litestar_auth.models.user.User` (e.g. custom ``user`` table).

The package namespace still supports ``from litestar_auth.models import User, OAuthAccount`` via
lazy attributes (PEP 562). Static type checkers use the ``TYPE_CHECKING`` imports below.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from litestar_auth.models.oauth import OAuthAccount
    from litestar_auth.models.user import User

__all__ = ("OAuthAccount", "User")


def __getattr__(name: str) -> object:
    """Load ``User`` or ``OAuthAccount`` on demand.

    Returns:
        The requested ORM model class.

    Raises:
        AttributeError: If ``name`` is not a public export.
    """
    if name == "User":
        from litestar_auth.models.user import User as _User

        return _User
    if name == "OAuthAccount":
        from litestar_auth.models.oauth import OAuthAccount as _OAuthAccount

        return _OAuthAccount
    msg = f"module {__name__!r} has no attribute {name!r}"
    raise AttributeError(msg)


def __dir__() -> list[str]:
    """Return public model names for discovery."""
    return sorted(__all__)
