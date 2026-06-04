"""Plugin-owned organization activation routes."""

from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass
from typing import TYPE_CHECKING, Any, Never, Protocol, cast, runtime_checkable

from litestar import Controller, Request, post
from litestar.di import NamedDependency
from litestar.response import Response

from litestar_auth._plugin.controller_factory import ControllerFactoryKit
from litestar_auth._tenant_resolution import _normalize_tenant_slug
from litestar_auth.authentication.backend import AuthenticationBackend
from litestar_auth.controllers._error_responses import raise_client_error
from litestar_auth.controllers._utils import (
    RequestBodyErrorConfig,
    _create_before_request_handler,
    _create_request_body_exception_handlers,
)
from litestar_auth.db import BaseOrganizationStore
from litestar_auth.exceptions import ErrorCode
from litestar_auth.guards import is_authenticated
from litestar_auth.payloads import SwitchOrganizationRequest  # noqa: TC001
from litestar_auth.types import UserProtocol

if TYPE_CHECKING:
    from litestar.openapi.spec import SecurityRequirement

    from litestar_auth._plugin.config import StartupBackendInventory, StartupBackendTemplate
    from litestar_auth.ratelimit import AuthRateLimitConfig

_OrganizationStoreDep = NamedDependency[BaseOrganizationStore[Any, Any, Any, Any]]
_AuthBackendsDep = NamedDependency[Sequence[AuthenticationBackend[Any, Any]]]

SWITCH_ORGANIZATION_DENIED_DETAIL = "Organization access denied."


@runtime_checkable
class OrganizationTokenStrategy[UP: UserProtocol[Any]](Protocol):
    """Strategy behavior required to issue an organization-bound access token."""

    async def write_token_for_organization(self, user: UP, organization: str) -> str:
        """Issue a token carrying a verified organization claim."""


@dataclass(frozen=True, slots=True)
class OrganizationControllerConfig[UP: UserProtocol[Any], ID]:
    """Static settings for the switch-organization controller."""

    backend: StartupBackendTemplate[UP, ID]
    backend_inventory: StartupBackendInventory[UP, ID]
    backend_index: int
    path: str = "/auth"
    slug_min_length: int = 1
    slug_max_length: int = 128
    rate_limit_config: AuthRateLimitConfig | None = None
    security: Sequence[SecurityRequirement] | None = None


def create_organization_controller[UP: UserProtocol[Any], ID](
    config: OrganizationControllerConfig[UP, ID],
) -> type[Controller]:
    """Return a controller exposing organization activation for one backend."""
    factory_kit = ControllerFactoryKit[UP, ID](
        backend_inventory=config.backend_inventory,
        backend_index=config.backend_index,
    )
    exception_handlers = _create_request_body_exception_handlers(
        RequestBodyErrorConfig(
            validation_detail="Invalid switch-organization payload.",
            validation_code=ErrorCode.REQUEST_BODY_INVALID,
        ),
    )
    switch_rate_limit = config.rate_limit_config.organization_switch if config.rate_limit_config else None

    class OrganizationController(Controller):
        """Organization activation endpoints."""

        @post(
            "/switch-organization",
            guards=[is_authenticated],
            status_code=200,
            before_request=_create_before_request_handler(switch_rate_limit),
            security=config.security,
            exception_handlers=exception_handlers,
        )
        async def switch_organization(  # noqa: PLR6301
            self,
            request: Request[Any, Any, Any],
            data: SwitchOrganizationRequest,
            litestar_auth_backends: _AuthBackendsDep,
            litestar_auth_organization_store: _OrganizationStoreDep,
        ) -> Response[Any]:
            return await _handle_switch_organization(
                request,
                data,
                backend=factory_kit.resolve_backend(litestar_auth_backends),
                organization_store=litestar_auth_organization_store,
                slug_bounds=(config.slug_min_length, config.slug_max_length),
            )

    return ControllerFactoryKit.finalize_controller(
        OrganizationController,
        module=__name__,
        name=f"{config.backend.name}OrganizationController",
        path=config.path,
    )


def backend_supports_organization_tokens(backend: object) -> bool:
    """Return whether the backend strategy can mint organization-bound tokens."""
    return isinstance(getattr(backend, "strategy", None), OrganizationTokenStrategy)


async def _handle_switch_organization[UP: UserProtocol[Any]](
    request: Request[Any, Any, Any],
    data: SwitchOrganizationRequest,
    *,
    backend: AuthenticationBackend[UP, Any],
    organization_store: BaseOrganizationStore[Any, Any, Any, Any],
    slug_bounds: tuple[int, int],
) -> Response[Any]:
    """Verify target membership and return a transport-shaped login response.

    Returns:
        Login-token response produced by the configured transport.
    """
    slug = _normalize_requested_slug(data.organization_slug, min_length=slug_bounds[0], max_length=slug_bounds[1])
    if slug is None:
        _raise_switch_denied()

    user = cast("UP", request.user)
    user_id = getattr(user, "id", None)
    organization = await organization_store.get_organization_by_slug(slug)
    organization_id = getattr(organization, "id", None)
    membership = (
        await organization_store.get_membership(organization_id=organization_id, user_id=user_id)
        if organization_id is not None and user_id is not None
        else None
    )
    if organization_id is None or user_id is None or membership is None:
        _raise_switch_denied()

    strategy = backend.strategy
    if not isinstance(strategy, OrganizationTokenStrategy):  # pragma: no cover - controller assembly filters this
        _raise_switch_denied()

    token_strategy = cast("OrganizationTokenStrategy[UP]", strategy)
    token = await token_strategy.write_token_for_organization(user, slug)
    return backend.transport.set_login_token(Response(content=None), token)


def _normalize_requested_slug(raw_slug: str, *, min_length: int, max_length: int) -> str | None:
    slug = _normalize_tenant_slug(raw_slug)
    if slug is None or len(slug) < min_length or len(slug) > max_length:
        return None
    return slug


def _raise_switch_denied() -> Never:
    raise_client_error(
        status_code=403,
        detail=SWITCH_ORGANIZATION_DENIED_DETAIL,
        error_code=ErrorCode.ORGANIZATION_SWITCH_DENIED,
    )


__all__ = (
    "SWITCH_ORGANIZATION_DENIED_DETAIL",
    "OrganizationControllerConfig",
    "backend_supports_organization_tokens",
    "create_organization_controller",
)
