"""Controller assembly helpers for the auth plugin facade."""

# ruff: noqa: RUF067

from __future__ import annotations

import sys

from litestar_auth._plugin.controllers import _core as _core
from litestar_auth._plugin.controllers._core import (
    _append_account_feature_controllers as _append_account_feature_controllers,
)
from litestar_auth._plugin.controllers._core import (
    _append_optional_feature_controllers as _append_optional_feature_controllers,
)
from litestar_auth._plugin.controllers._core import (
    _append_session_feature_controllers as _append_session_feature_controllers,
)
from litestar_auth._plugin.controllers._core import (
    _build_auth_controllers as _build_auth_controllers,
)
from litestar_auth._plugin.controllers._core import (
    backend_auth_path as backend_auth_path,
)
from litestar_auth._plugin.controllers._core import (
    build_controllers as build_controllers,
)
from litestar_auth._plugin.controllers._core import (
    create_auth_controller as create_auth_controller,
)
from litestar_auth._plugin.controllers._core import (
    create_session_devices_controller as create_session_devices_controller,
)
from litestar_auth._plugin.controllers._core import (
    register_schema_kwargs as register_schema_kwargs,
)
from litestar_auth._plugin.controllers._core import (
    user_read_schema_kwargs as user_read_schema_kwargs,
)
from litestar_auth._plugin.controllers._core import (
    users_schema_kwargs as users_schema_kwargs,
)

globals().update(
    {name: value for name, value in vars(_core).items() if not (name.startswith("__") and name.endswith("__"))},
)
sys.modules[__name__] = _core
