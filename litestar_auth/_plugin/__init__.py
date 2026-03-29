"""Internal-only plugin implementation modules and compatibility exports.

`litestar_auth.plugin` is the stable public entry point for plugin consumers.
Names exported from this package exist for internal composition and for
compatibility shims only.
"""

from litestar_auth._plugin.config import (
    DEFAULT_BACKENDS_DEPENDENCY_KEY,
    DEFAULT_CONFIG_DEPENDENCY_KEY,
    DEFAULT_CSRF_COOKIE_NAME,
    DEFAULT_USER_MANAGER_DEPENDENCY_KEY,
    DEFAULT_USER_MODEL_DEPENDENCY_KEY,
    OAUTH_ASSOCIATE_USER_MANAGER_DEPENDENCY_KEY,
    LitestarAuthConfig,
)
from litestar_auth._plugin.session_binding import (
    _ScopedUserDatabaseProxy,
    _UserManagerFactory,
)

__all__ = (
    "DEFAULT_BACKENDS_DEPENDENCY_KEY",
    "DEFAULT_CONFIG_DEPENDENCY_KEY",
    "DEFAULT_CSRF_COOKIE_NAME",
    "DEFAULT_USER_MANAGER_DEPENDENCY_KEY",
    "DEFAULT_USER_MODEL_DEPENDENCY_KEY",
    "OAUTH_ASSOCIATE_USER_MANAGER_DEPENDENCY_KEY",
    "LitestarAuthConfig",
    "_ScopedUserDatabaseProxy",
    "_UserManagerFactory",
)
