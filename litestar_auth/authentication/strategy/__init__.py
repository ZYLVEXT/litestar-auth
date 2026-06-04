"""Issue, validate, rotate, and revoke tokens (JWT, database, or Redis).

Strategies pair with :mod:`litestar_auth.authentication.transport` implementations
inside :class:`~litestar_auth.authentication.backend.AuthenticationBackend`.

``DatabaseTokenModels`` is the explicit contract for ``DatabaseTokenStrategy`` when you swap in
mixin-composed token ORM classes. The explicit bundled-token bootstrap helper lives at
``litestar_auth.models.import_token_orm_models()``.
"""

from litestar_auth.authentication.strategy._api_key_nonce_store import (
    ApiKeyNonceStore,
    ApiKeyNonceStoreResult,
    InMemoryApiKeyNonceStore,
    RedisApiKeyNonceStore,
    RedisApiKeyNonceStoreClient,
)
from litestar_auth.authentication.strategy.api_key import ApiKeyContext, ApiKeyStrategy, ApiKeyStrategyConfig
from litestar_auth.authentication.strategy.base import (
    ContextualStrategy,
    RefreshableStrategy,
    Strategy,
    UserManagerProtocol,
)
from litestar_auth.authentication.strategy.db import DatabaseTokenStrategy, DatabaseTokenStrategyConfig
from litestar_auth.authentication.strategy.db_models import DatabaseTokenModels
from litestar_auth.authentication.strategy.jwt import JWTContext, JWTStrategy, JWTStrategyConfig
from litestar_auth.authentication.strategy.redis import RedisTokenStrategy, RedisTokenStrategyConfig

__all__ = (
    "ApiKeyContext",
    "ApiKeyNonceStore",
    "ApiKeyNonceStoreResult",
    "ApiKeyStrategy",
    "ApiKeyStrategyConfig",
    "ContextualStrategy",
    "DatabaseTokenModels",
    "DatabaseTokenStrategy",
    "DatabaseTokenStrategyConfig",
    "InMemoryApiKeyNonceStore",
    "JWTContext",
    "JWTStrategy",
    "JWTStrategyConfig",
    "RedisApiKeyNonceStore",
    "RedisApiKeyNonceStoreClient",
    "RedisTokenStrategy",
    "RedisTokenStrategyConfig",
    "RefreshableStrategy",
    "Strategy",
    "UserManagerProtocol",
)
