"""Issue, validate, rotate, and revoke server-side database or Redis sessions.

Strategies pair with :mod:`litestar_auth.authentication.transport` implementations
inside :class:`~litestar_auth.authentication.backend.AuthenticationBackend`.

``DatabaseTokenModels`` is the explicit contract for ``DatabaseTokenStrategy`` when you swap in
mixin-composed token ORM classes. The explicit bundled-token bootstrap helper lives at
``litestar_auth.models.import_token_orm_models()``.
"""

from litestar_auth.authentication.strategy.base import (
    HumanSessionAuthenticated,
    HumanSessionStrategy,
    RefreshableStrategy,
    Strategy,
    UserManagerProtocol,
)
from litestar_auth.authentication.strategy.db import DatabaseTokenStrategy, DatabaseTokenStrategyConfig
from litestar_auth.authentication.strategy.db_models import DatabaseTokenModels
from litestar_auth.authentication.strategy.redis import RedisTokenStrategy, RedisTokenStrategyConfig

__all__ = (
    "DatabaseTokenModels",
    "DatabaseTokenStrategy",
    "DatabaseTokenStrategyConfig",
    "HumanSessionAuthenticated",
    "HumanSessionStrategy",
    "RedisTokenStrategy",
    "RedisTokenStrategyConfig",
    "RefreshableStrategy",
    "Strategy",
    "UserManagerProtocol",
)
