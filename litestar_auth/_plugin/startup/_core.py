"""Startup hook orchestration for plugin app initialization."""

from __future__ import annotations

import importlib
from collections.abc import Callable
from functools import cache
from typing import TYPE_CHECKING, Any, cast
from urllib.parse import urlsplit

from litestar_auth._plugin._hooks import iter_feature_wiring
from litestar_auth._plugin._redirect_validation import _is_unsafe_redirect_host
from litestar_auth._plugin.oauth_contract import _build_oauth_route_registration_contract
from litestar_auth._plugin.startup._requirements import (
    _require_clean_oauth_redirect_base_url,
    _require_https_oauth_redirect_base_url,
    has_configured_oauth_providers,
    has_configured_oauth_providers_for,
    require_oauth_token_encryption_for_configured_providers,
    require_refreshable_strategy_when_enable_refresh,
    require_shared_rate_limit_backends_for_multiworker,
)
from litestar_auth._plugin.startup._warnings import (
    SecurityWarning,
    _collect_process_local_rate_limit_endpoint_names,
    warn_insecure_plugin_startup_defaults,
)
from litestar_auth.exceptions import ConfigurationError

if TYPE_CHECKING:
    from litestar.config.app import AppConfig

    from litestar_auth._plugin.config import LitestarAuthConfig

type StartupHook = Callable[[], None]

__all__ = (
    "SecurityWarning",
    "_collect_process_local_rate_limit_endpoint_names",
    "_is_unsafe_redirect_host",
    "has_configured_oauth_providers",
    "has_configured_oauth_providers_for",
)


@cache
def _load_bundled_token_orm_models() -> tuple[object, object]:
    """Load the bundled DB-token ORM classes exactly once per process.

    Returns:
        The bundled access-token and refresh-token ORM classes.
    """
    models_module = importlib.import_module("litestar_auth.models")
    return cast("Any", models_module).import_token_orm_models()


def bootstrap_bundled_token_orm_models(config: LitestarAuthConfig[Any, Any]) -> None:
    """Load bundled token ORM models during plugin app init when runtime uses them."""
    from litestar_auth._plugin.database_token import (  # noqa: PLC0415
        _uses_bundled_database_token_models,
    )

    if _uses_bundled_database_token_models(config):
        _load_bundled_token_orm_models()


def run_before_startup_wiring(
    *,
    config: LitestarAuthConfig[Any, Any],
    app_config: AppConfig,
    require_oauth_key: object,
) -> None:
    """Run configured plugin startup hooks in descriptor order."""
    startup_hooks = _build_startup_hook_map(
        config=config,
        app_config=app_config,
        require_oauth_key=require_oauth_key,
    )
    for wiring in iter_feature_wiring(config):
        for hook_name in wiring.before_startup:
            startup_hooks[hook_name]()


def _build_startup_hook_map(
    *,
    config: LitestarAuthConfig[Any, Any],
    app_config: AppConfig,
    require_oauth_key: object,
) -> dict[str, StartupHook]:
    """Return named startup hooks used by ``FeatureWiring`` descriptors."""
    return {
        "require_shared_rate_limit_backends_for_multiworker": lambda: (
            require_shared_rate_limit_backends_for_multiworker(
                config,
            )
        ),
        "require_refreshable_strategy_when_enable_refresh": lambda: require_refreshable_strategy_when_enable_refresh(
            config,
        ),
        "warn_insecure_plugin_startup_defaults": lambda: warn_insecure_plugin_startup_defaults(config),
        "require_oauth_token_encryption_for_configured_providers": lambda: (
            require_oauth_token_encryption_for_configured_providers(config=config, require_key=require_oauth_key)
        ),
        "require_secure_oauth_redirect_in_production": lambda: require_secure_oauth_redirect_in_production(
            config=config,
            app_config=app_config,
        ),
        "bootstrap_bundled_token_orm_models": lambda: bootstrap_bundled_token_orm_models(config),
    }


def require_secure_oauth_redirect_in_production(
    *,
    config: LitestarAuthConfig[Any, Any],
    app_config: AppConfig,
) -> None:
    """Fail closed when plugin-owned OAuth redirects use insecure production origins."""
    if config.unsafe_testing or getattr(app_config, "debug", False):
        return

    oauth_config = config.oauth_config
    contract = _build_oauth_route_registration_contract(
        auth_path=config.auth_path,
        oauth_config=oauth_config,
    )
    if not contract.has_plugin_owned_login_routes:
        return
    redirect_base_url = contract.redirect_base_url
    if redirect_base_url is None:  # pragma: no cover - validation guarantees this when providers exist
        return

    parsed_redirect_base_url = urlsplit(redirect_base_url)
    _require_https_oauth_redirect_base_url(redirect_base_url, parsed_redirect_base_url.scheme)
    _require_public_oauth_redirect_host(
        redirect_base_url,
        parsed_redirect_base_url.hostname,
        strict=oauth_config.oauth_redirect_dns_strict if oauth_config is not None else True,
    )
    _require_clean_oauth_redirect_base_url(
        redirect_base_url,
        has_userinfo=parsed_redirect_base_url.username is not None or parsed_redirect_base_url.password is not None,
        has_query=bool(parsed_redirect_base_url.query),
        has_fragment=bool(parsed_redirect_base_url.fragment),
    )


def _require_public_oauth_redirect_host(redirect_base_url: str, host: str | None, *, strict: bool = False) -> None:
    if host is not None and not _is_unsafe_redirect_host(host, strict=strict):
        return
    msg = (
        "Plugin-managed OAuth routes require oauth_redirect_base_url to use a routable public HTTPS origin "
        "(no loopback, private, link-local, multicast, or reserved hosts) in production. "
        f"Received {redirect_base_url!r}. Use AppConfig(debug=True) or unsafe_testing=True only "
        "for explicit local-development and test recipes."
    )
    raise ConfigurationError(msg)
