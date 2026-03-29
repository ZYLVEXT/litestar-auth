"""Issue, validate, rotate, and revoke tokens (JWT, database, or Redis).

Strategies pair with :mod:`litestar_auth.authentication.transport` implementations
inside :class:`~litestar_auth.authentication.backend.AuthenticationBackend`.
"""

from litestar_auth.authentication.strategy.base import RefreshableStrategy, Strategy, UserManagerProtocol
from litestar_auth.authentication.strategy.db import DatabaseTokenStrategy
from litestar_auth.authentication.strategy.jwt import JWTStrategy
from litestar_auth.authentication.strategy.redis import RedisTokenStrategy

__all__ = (
    "DatabaseTokenStrategy",
    "JWTStrategy",
    "RedisTokenStrategy",
    "RefreshableStrategy",
    "Strategy",
    "UserManagerProtocol",
)
