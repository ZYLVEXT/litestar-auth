"""OAuth route registration contract for plugin-owned login and associate routes."""

# Test-suite reload-coverage pattern note:
# `_current_oauth_provider_config_type` lazily resolves `OAuthProviderConfig` so
# callers pick up the post-reload class identity after tests call
# `importlib.reload(...)`. The reload pattern is load-bearing for the 100%
# coverage gate; removing this helper requires first replacing the
# coverage-startup mechanism. See the investigation outcome at
# refactoring-test-reload-investigation.json (REFAC-001).

from __future__ import annotations

from dataclasses import dataclass
from importlib import import_module
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from collections.abc import Mapping, Sequence  # pragma: no cover

    from litestar_auth._plugin.config import OAuthConfig  # pragma: no cover
    from litestar_auth.config import OAuthProviderConfig  # pragma: no cover


def _current_oauth_provider_config_type() -> type[OAuthProviderConfig]:
    """Resolve ``OAuthProviderConfig`` lazily for OAuth provider normalization.

    This lets ``_normalize_oauth_provider_inventory()`` pick up the post-reload
    class identity if a test calls ``importlib.reload(litestar_auth.config)``.
    Test-infrastructure helper -- see the module-level note above.

    Returns:
        The current ``OAuthProviderConfig`` type from ``litestar_auth.config``.
    """
    return import_module("litestar_auth.config").OAuthProviderConfig


@dataclass(frozen=True, slots=True)
class _OAuthRouteRegistrationContract:
    """Internal contract describing plugin-owned OAuth login and associate routes."""

    providers: tuple[OAuthProviderConfig, ...]
    oauth_provider_scopes: dict[str, tuple[str, ...]]
    include_oauth_associate: bool
    oauth_cookie_secure: bool
    oauth_associate_by_email: bool
    oauth_trust_provider_email_verified: bool
    oauth_flow_cookie_secret: str | None
    login_path: str
    associate_path: str
    redirect_base_url: str | None

    @property
    def has_configured_providers(self) -> bool:
        """Return whether any plugin-owned OAuth provider inventory was declared."""
        return bool(self.providers)

    @property
    def has_plugin_owned_login_routes(self) -> bool:
        """Return whether the plugin will auto-mount OAuth login routes."""
        return bool(self.providers)

    @property
    def has_plugin_owned_associate_routes(self) -> bool:
        """Return whether the plugin will auto-mount associate routes."""
        return bool(self.providers) and self.include_oauth_associate

    @property
    def login_redirect_base_url(self) -> str | None:
        """Return the absolute OAuth login redirect base URL when routes are mounted."""
        if not self.has_plugin_owned_login_routes or self.redirect_base_url is None:
            return None
        return f"{self.redirect_base_url.rstrip('/')}/oauth"

    @property
    def associate_redirect_base_url(self) -> str | None:
        """Return the absolute OAuth associate redirect base URL when routes are mounted."""
        if not self.has_plugin_owned_associate_routes or self.redirect_base_url is None:
            return None
        return f"{self.redirect_base_url.rstrip('/')}/associate"


def _normalize_oauth_provider_inventory(
    providers: Sequence[OAuthProviderConfig] | None,
) -> tuple[OAuthProviderConfig, ...]:
    """Return a stable tuple of normalized OAuth provider entries."""
    if not providers:
        return ()
    oauth_provider_config_type = _current_oauth_provider_config_type()
    return tuple(oauth_provider_config_type.coerce(item) for item in providers)


def _normalize_oauth_scopes(scopes: Sequence[str]) -> tuple[str, ...]:
    """Return a normalized tuple of configured OAuth scopes.

    Raises:
        TypeError: If any configured scope is not a string.
        ValueError: If any configured scope is empty or contains whitespace.
    """
    normalized_scopes: list[str] = []
    seen_scopes: set[str] = set()
    for raw_scope in scopes:
        if not isinstance(raw_scope, str):
            msg = "oauth_provider_scopes values must be strings."
            raise TypeError(msg)
        scope = raw_scope.strip()
        if not scope:
            msg = "oauth_provider_scopes values must be non-empty strings."
            raise ValueError(msg)
        if any(character.isspace() for character in scope):
            msg = "oauth_provider_scopes values must be individual tokens without embedded whitespace."
            raise ValueError(msg)
        if scope not in seen_scopes:
            normalized_scopes.append(scope)
            seen_scopes.add(scope)
    return tuple(normalized_scopes)


def _normalize_oauth_provider_scopes(
    *,
    providers: tuple[OAuthProviderConfig, ...],
    provider_scopes: Mapping[str, Sequence[str]],
) -> dict[str, tuple[str, ...]]:
    """Return normalized per-provider OAuth scopes keyed by provider name.

    Raises:
        ValueError: If provider scopes reference an unknown provider name or contain invalid scopes.
    """
    normalized_provider_scopes: dict[str, tuple[str, ...]] = {}
    configured_provider_names = {entry.name for entry in providers}
    unknown_provider_names = sorted(set(provider_scopes) - configured_provider_names)
    if unknown_provider_names:
        joined_names = ", ".join(unknown_provider_names)
        msg = f"oauth_provider_scopes contains unknown provider names: {joined_names}."
        raise ValueError(msg)

    for provider_name, scopes in provider_scopes.items():
        normalized_scopes = _normalize_oauth_scopes(scopes)
        if normalized_scopes:
            normalized_provider_scopes[provider_name] = normalized_scopes

    return normalized_provider_scopes


def _build_oauth_route_registration_contract(
    *,
    auth_path: str,
    oauth_config: OAuthConfig | None,
) -> _OAuthRouteRegistrationContract:
    """Return the deterministic plugin OAuth route-registration contract.

    ``oauth_providers`` is the single plugin-owned OAuth provider inventory. When it
    is configured, the plugin auto-mounts provider login routes under
    ``{auth_path}/oauth/{provider}/...``. ``include_oauth_associate=True`` extends
    that same provider inventory with authenticated account-linking routes under
    ``{auth_path}/associate/{provider}/...``. Redirect callbacks use the explicit
    public ``oauth_redirect_base_url`` instead of an implicit localhost fallback.
    """
    base_auth_path = auth_path.rstrip("/") or "/"
    login_path = f"{base_auth_path}/oauth" if base_auth_path != "/" else "/oauth"
    associate_path = f"{base_auth_path}/associate" if base_auth_path != "/" else "/associate"
    if oauth_config is None:
        return _OAuthRouteRegistrationContract(
            providers=(),
            oauth_provider_scopes={},
            include_oauth_associate=False,
            oauth_cookie_secure=True,
            oauth_associate_by_email=False,
            oauth_trust_provider_email_verified=False,
            oauth_flow_cookie_secret=None,
            login_path=login_path,
            associate_path=associate_path,
            redirect_base_url=None,
        )

    providers = _normalize_oauth_provider_inventory(oauth_config.oauth_providers)
    redirect_base_url = oauth_config.oauth_redirect_base_url or None
    return _OAuthRouteRegistrationContract(
        providers=providers,
        oauth_provider_scopes=_normalize_oauth_provider_scopes(
            providers=providers,
            provider_scopes=oauth_config.oauth_provider_scopes,
        ),
        include_oauth_associate=oauth_config.include_oauth_associate,
        oauth_cookie_secure=oauth_config.oauth_cookie_secure,
        oauth_associate_by_email=oauth_config.oauth_associate_by_email,
        oauth_trust_provider_email_verified=oauth_config.oauth_trust_provider_email_verified,
        oauth_flow_cookie_secret=oauth_config.oauth_flow_cookie_secret,
        login_path=login_path,
        associate_path=associate_path,
        redirect_base_url=redirect_base_url,
    )
