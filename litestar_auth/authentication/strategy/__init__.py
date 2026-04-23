"""Issue, validate, rotate, and revoke tokens (JWT, database, or Redis).

Strategies pair with :mod:`litestar_auth.authentication.transport` implementations
inside :class:`~litestar_auth.authentication.backend.AuthenticationBackend`.

``DatabaseTokenModels`` is the explicit contract for ``DatabaseTokenStrategy`` when you swap in
mixin-composed token ORM classes. The explicit bundled-token bootstrap helper lives at
``litestar_auth.models.import_token_orm_models()``.
"""

from litestar_auth.authentication.strategy.base import RefreshableStrategy, Strategy, UserManagerProtocol
from litestar_auth.authentication.strategy.db import DatabaseTokenStrategy
from litestar_auth.authentication.strategy.db_models import DatabaseTokenModels
from litestar_auth.authentication.strategy.jwt import JWTStrategy
from litestar_auth.authentication.strategy.redis import RedisTokenStrategy

__all__ = (
    "DatabaseTokenModels",
    "DatabaseTokenStrategy",
    "JWTStrategy",
    "RedisTokenStrategy",
    "RefreshableStrategy",
    "Strategy",
    "UserManagerProtocol",
)
