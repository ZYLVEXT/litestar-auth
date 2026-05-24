"""Startup warnings and fail-closed guards for plugin app initialization."""

# ruff: noqa: RUF067

from __future__ import annotations

import sys

from litestar_auth._plugin.startup import _core as _core
from litestar_auth._plugin.startup._core import (
    SecurityWarning as SecurityWarning,
)
from litestar_auth._plugin.startup._core import (
    _collect_process_local_rate_limit_endpoint_names as _collect_process_local_rate_limit_endpoint_names,
)
from litestar_auth._plugin.startup._core import (
    _load_bundled_token_orm_models as _load_bundled_token_orm_models,
)
from litestar_auth._plugin.startup._core import (
    bootstrap_bundled_token_orm_models as bootstrap_bundled_token_orm_models,
)
from litestar_auth._plugin.startup._core import (
    has_configured_oauth_providers as has_configured_oauth_providers,
)
from litestar_auth._plugin.startup._core import (
    has_configured_oauth_providers_for as has_configured_oauth_providers_for,
)
from litestar_auth._plugin.startup._core import (
    importlib as importlib,
)
from litestar_auth._plugin.startup._core import (
    require_oauth_token_encryption_for_configured_providers as require_oauth_token_encryption_for_configured_providers,
)
from litestar_auth._plugin.startup._core import (
    require_refreshable_strategy_when_enable_refresh as require_refreshable_strategy_when_enable_refresh,
)
from litestar_auth._plugin.startup._core import (
    require_secure_oauth_redirect_in_production as require_secure_oauth_redirect_in_production,
)
from litestar_auth._plugin.startup._core import (
    require_shared_rate_limit_backends_for_multiworker as require_shared_rate_limit_backends_for_multiworker,
)
from litestar_auth._plugin.startup._core import (
    run_before_startup_wiring as run_before_startup_wiring,
)
from litestar_auth._plugin.startup._core import (
    warn_insecure_plugin_startup_defaults as warn_insecure_plugin_startup_defaults,
)

globals().update(
    {name: value for name, value in vars(_core).items() if not (name.startswith("__") and name.endswith("__"))},
)
sys.modules[__name__] = _core
