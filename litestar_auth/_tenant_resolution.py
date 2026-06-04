"""Request-derived tenant resolution helpers."""

from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING, Any, Protocol

from litestar_auth._roles import normalize_role_name
from litestar_auth.authentication.strategy.jwt import JWTContext
from litestar_auth.ratelimit._client_host import _get_header_value, _normalize_host_value, _request_host

if TYPE_CHECKING:
    from litestar.connection import ASGIConnection

DEFAULT_ORGANIZATION_HEADER = "X-Organization"

__all__ = (
    "DEFAULT_ORGANIZATION_HEADER",
    "ClaimTenantResolver",
    "HeaderTenantResolver",
    "SubdomainTenantResolver",
    "TenantResolver",
)


class TenantResolver(Protocol):
    """Request seam for resolving an untrusted normalized organization slug."""

    def __call__(self, connection: ASGIConnection[Any, Any, Any, Any]) -> str | None:
        """Return a normalized organization slug, or ``None`` when unavailable."""


def _normalize_tenant_slug(raw_slug: str) -> str | None:
    """Return the organization-slug normalization used by the ORM mixin."""
    try:
        return normalize_role_name(raw_slug)
    except (TypeError, ValueError):
        return None


@dataclass(frozen=True, slots=True)
class HeaderTenantResolver:
    """Resolve an untrusted organization slug from one request header."""

    header_name: str = DEFAULT_ORGANIZATION_HEADER

    def __call__(self, connection: ASGIConnection[Any, Any, Any, Any]) -> str | None:
        """Return the normalized header value, or ``None`` when absent or blank."""
        raw_slug = _get_header_value(connection.headers, self.header_name)
        if raw_slug is None:
            return None
        return _normalize_tenant_slug(raw_slug)


@dataclass(frozen=True, slots=True)
class ClaimTenantResolver:
    """Resolve a trusted organization slug from verified JWT authentication context."""

    def __call__(self, connection: ASGIConnection[Any, Any, Any, Any]) -> str | None:
        """Return the normalized signed JWT organization claim, or ``None`` when unavailable."""
        auth_context = connection.scope.get("auth")
        if not isinstance(auth_context, JWTContext) or auth_context.organization is None:
            return None
        return _normalize_tenant_slug(auth_context.organization)


@dataclass(frozen=True, slots=True)
class SubdomainTenantResolver:
    """Resolve an untrusted organization slug from the host subdomain."""

    root_domain: str

    def __call__(self, connection: ASGIConnection[Any, Any, Any, Any]) -> str | None:
        """Return the normalized subdomain slug, or ``None`` when unavailable."""
        host = _request_host(connection)
        root_domain = _normalize_host_value(self.root_domain)
        if host is None or root_domain is None:
            return None
        if host == root_domain:
            return None

        suffix = f".{root_domain}"
        if not host.endswith(suffix):
            return None

        raw_subdomain = host[: -len(suffix)]
        return _normalize_tenant_slug(raw_subdomain)
