"""Role administration helpers for SQLAlchemy-backed plugin integrations."""

# ruff: noqa: RUF067

from __future__ import annotations

import sys

from litestar_auth._plugin.role_admin import _core as _core
from litestar_auth._plugin.role_admin._core import (
    RoleAdminRoleNotFoundError as RoleAdminRoleNotFoundError,
)
from litestar_auth._plugin.role_admin._core import (
    RoleAdminUserNotFoundError as RoleAdminUserNotFoundError,
)
from litestar_auth._plugin.role_admin._core import (
    RoleModelFamily as RoleModelFamily,
)
from litestar_auth._plugin.role_admin._core import (
    SQLAlchemyRoleAdmin as SQLAlchemyRoleAdmin,
)
from litestar_auth._plugin.role_admin._core import (
    SystemManagedRoleError as SystemManagedRoleError,
)
from litestar_auth._plugin.role_admin._core import (
    UserRoleMembership as UserRoleMembership,
)
from litestar_auth._plugin.role_admin._core import (
    _ManagerLifecycleRoleUpdater as _ManagerLifecycleRoleUpdater,
)
from litestar_auth._plugin.role_admin._core import (
    _RoleLifecycleManager as _RoleLifecycleManager,
)
from litestar_auth._plugin.role_admin._core import (
    resolve_role_model_family as resolve_role_model_family,
)

globals().update(
    {name: value for name, value in vars(_core).items() if not (name.startswith("__") and name.endswith("__"))},
)
sys.modules[__name__] = _core
