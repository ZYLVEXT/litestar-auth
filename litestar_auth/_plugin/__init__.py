"""Internal-only plugin implementation modules.

`litestar_auth.plugin` is the stable public entry point for plugin consumers.
Names exported from this package exist for internal composition only. Handler
helpers live in ``litestar_auth._plugin.exception_handlers`` and dependency
helpers live in ``litestar_auth._plugin.dependencies``.
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

__all__ = (
    "DEFAULT_BACKENDS_DEPENDENCY_KEY",
    "DEFAULT_CONFIG_DEPENDENCY_KEY",
    "DEFAULT_CSRF_COOKIE_NAME",
    "DEFAULT_USER_MANAGER_DEPENDENCY_KEY",
    "DEFAULT_USER_MODEL_DEPENDENCY_KEY",
    "OAUTH_ASSOCIATE_USER_MANAGER_DEPENDENCY_KEY",
    "LitestarAuthConfig",
)
