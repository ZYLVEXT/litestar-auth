"""OAuth route-registration validation for plugin configuration."""

from __future__ import annotations

from typing import TYPE_CHECKING

from litestar_auth._plugin.oauth_contract import (
    _build_oauth_route_registration_contract,
    _OAuthRouteRegistrationContract,
)
from litestar_auth.config import MINIMUM_SECRET_LENGTH, OAuthProviderConfig, validate_secret_length
from litestar_auth.exceptions import ConfigurationError

if TYPE_CHECKING:
    from litestar_auth._plugin.config import OAuthConfig


def validate_oauth_route_registration_config(oauth_config: OAuthConfig | None, *, auth_path: str) -> None:
    """Validate the deterministic plugin OAuth route-registration contract."""
    if oauth_config is None:
        return

    contract = _build_oauth_route_registration_contract(
        auth_path=auth_path,
        oauth_config=oauth_config,
    )
    _validate_unique_oauth_provider_names(
        providers=contract.providers,
        field_name="oauth_providers",
    )
    _validate_oauth_route_provider_contract(oauth_config=oauth_config, contract=contract)
    _validate_oauth_flow_cookie_secret(oauth_config=oauth_config, contract=contract)


def _validate_oauth_route_provider_contract(
    *,
    oauth_config: OAuthConfig,
    contract: _OAuthRouteRegistrationContract,
) -> None:
    """Validate plugin-owned OAuth route flags against the declared provider inventory."""
    _validate_oauth_associate_requires_providers(contract)
    _validate_oauth_redirect_base_url_requires_providers(oauth_config=oauth_config, contract=contract)
    _validate_oauth_providers_require_redirect_base_url(contract)
    _validate_oauth_associate_by_email_requires_providers(contract)
    _validate_oauth_trust_provider_email_verified_requires_providers(contract)


def _validate_oauth_associate_requires_providers(contract: _OAuthRouteRegistrationContract) -> None:
    """Validate that associate routes have a plugin-owned provider inventory.

    Raises:
        ValueError: If association routes are enabled without providers.
    """
    if contract.include_oauth_associate and not contract.providers:
        msg = "include_oauth_associate=True requires oauth_providers to be configured."
        raise ValueError(msg)


def _validate_oauth_redirect_base_url_requires_providers(
    *,
    oauth_config: OAuthConfig,
    contract: _OAuthRouteRegistrationContract,
) -> None:
    """Validate that redirect base URL settings correspond to plugin-owned providers.

    Raises:
        ValueError: If a redirect base URL is configured without providers.
    """
    if oauth_config.oauth_redirect_base_url and not contract.providers:
        msg = "oauth_redirect_base_url requires oauth_providers to be configured."
        raise ValueError(msg)


def _validate_oauth_providers_require_redirect_base_url(contract: _OAuthRouteRegistrationContract) -> None:
    """Validate that provider routes have an explicit public redirect base URL.

    Raises:
        ValueError: If providers are configured without a redirect base URL.
    """
    if contract.providers and contract.redirect_base_url is None:
        msg = "oauth_redirect_base_url is required when oauth_providers are configured."
        raise ValueError(msg)


def _validate_oauth_associate_by_email_requires_providers(contract: _OAuthRouteRegistrationContract) -> None:
    """Validate that email association settings correspond to plugin-owned providers.

    Raises:
        ValueError: If email association is configured without providers.
    """
    if contract.oauth_associate_by_email and not contract.providers:
        msg = "oauth_associate_by_email only affects plugin-owned OAuth login routes configured via oauth_providers."
        raise ValueError(msg)


def _validate_oauth_trust_provider_email_verified_requires_providers(
    contract: _OAuthRouteRegistrationContract,
) -> None:
    """Validate that provider email-trust settings correspond to plugin-owned providers.

    Raises:
        ValueError: If provider email-trust is configured without providers.
    """
    if contract.oauth_trust_provider_email_verified and not contract.providers:
        msg = (
            "oauth_trust_provider_email_verified only affects plugin-owned OAuth login routes configured "
            "via oauth_providers."
        )
        raise ValueError(msg)


def _validate_oauth_flow_cookie_secret(
    *,
    oauth_config: OAuthConfig,
    contract: _OAuthRouteRegistrationContract,
) -> None:
    """Validate OAuth flow cookie secret material when plugin-owned providers are configured.

    Raises:
        ConfigurationError: If plugin-owned OAuth routes are missing required secret material.
    """
    if oauth_config.oauth_flow_cookie_secret is not None:
        validate_secret_length(
            oauth_config.oauth_flow_cookie_secret,
            label="oauth_flow_cookie_secret",
            minimum_length=MINIMUM_SECRET_LENGTH,
        )

    if contract.providers and not oauth_config.oauth_flow_cookie_secret:
        msg = (
            "oauth_flow_cookie_secret is required when oauth_providers are configured. "
            'Generate one with `python -c "from secrets import token_urlsafe; print(token_urlsafe(32))"`.'
        )
        raise ConfigurationError(msg)


def _validate_unique_oauth_provider_names(
    *,
    providers: tuple[OAuthProviderConfig, ...],
    field_name: str,
) -> None:
    """Reject duplicate provider names within one declared OAuth inventory.

    Raises:
        ValueError: If a provider name appears more than once in the same inventory.
    """
    seen: set[str] = set()
    duplicates: list[str] = []
    for provider in providers:
        provider_name = provider.name
        if provider_name in seen and provider_name not in duplicates:
            duplicates.append(provider_name)
            continue
        seen.add(provider_name)

    if duplicates:
        duplicate_names = ", ".join(sorted(duplicates))
        msg = f"{field_name} must not contain duplicate provider names: {duplicate_names}."
        raise ValueError(msg)
