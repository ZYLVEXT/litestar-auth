"""ORM models package.

Use :func:`import_token_orm_models` from this package as the canonical explicit bootstrap helper
for the bundled token tables so mapper discovery stays under the models boundary. The strategy
layer still exposes the same helper only as a compatibility re-export for existing imports.

Import :mod:`litestar_auth.models.oauth` when you need
:class:`~litestar_auth.models.oauth.OAuthAccount` without registering the library
:class:`~litestar_auth.models.user.User` (for example, with a custom ``user`` table).

For custom user, token, or OAuth classes, compose the side-effect-free ORM mixins exposed here on
your own registry instead of copying fields or relationships from the reference models. When those
custom token tables back :class:`~litestar_auth.authentication.strategy.DatabaseTokenStrategy`,
pair them with :class:`~litestar_auth.authentication.strategy.DatabaseTokenModels`.

The package still supports ``from litestar_auth.models import User, OAuthAccount`` via lazy
attributes (PEP 562). Static type checkers use the ``TYPE_CHECKING`` imports below.
"""

from __future__ import annotations

from importlib import import_module
from typing import TYPE_CHECKING

from litestar_auth.models.tokens import import_token_orm_models

if TYPE_CHECKING:
    from litestar_auth.models.mixins import (
        AccessTokenMixin,
        OAuthAccountMixin,
        RefreshTokenMixin,
        RoleMixin,
        UserAuthRelationshipMixin,
        UserModelMixin,
        UserRoleAssociationMixin,
        UserRoleRelationshipMixin,
    )
    from litestar_auth.models.oauth import OAuthAccount
    from litestar_auth.models.role import Role, UserRole
    from litestar_auth.models.user import User

__all__ = (
    "AccessTokenMixin",
    "OAuthAccount",
    "OAuthAccountMixin",
    "RefreshTokenMixin",
    "Role",
    "RoleMixin",
    "User",
    "UserAuthRelationshipMixin",
    "UserModelMixin",
    "UserRole",
    "UserRoleAssociationMixin",
    "UserRoleRelationshipMixin",
    "import_token_orm_models",
)


def __getattr__(name: str) -> object:
    """Load lazy model exports on demand.

    Returns:
        The requested ORM model or mixin.

    Raises:
        AttributeError: If ``name`` is not a public export.
    """
    module_name = {
        "AccessTokenMixin": "litestar_auth.models.mixins",
        "OAuthAccount": "litestar_auth.models.oauth",
        "OAuthAccountMixin": "litestar_auth.models.mixins",
        "RefreshTokenMixin": "litestar_auth.models.mixins",
        "Role": "litestar_auth.models.role",
        "RoleMixin": "litestar_auth.models.mixins",
        "User": "litestar_auth.models.user",
        "UserAuthRelationshipMixin": "litestar_auth.models.mixins",
        "UserModelMixin": "litestar_auth.models.mixins",
        "UserRole": "litestar_auth.models.role",
        "UserRoleAssociationMixin": "litestar_auth.models.mixins",
        "UserRoleRelationshipMixin": "litestar_auth.models.mixins",
    }.get(name)
    if module_name is None:
        msg = f"module {__name__!r} has no attribute {name!r}"
        raise AttributeError(msg)
    return getattr(import_module(module_name), name)


def __dir__() -> list[str]:
    """Return public model names for discovery."""
    return sorted(__all__)
