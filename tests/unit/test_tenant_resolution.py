"""Tests for request-derived tenant resolution helpers."""

from __future__ import annotations

from typing import TYPE_CHECKING, Any, cast

import pytest
from litestar.connection import ASGIConnection

from litestar_auth._auth_model_mixins import OrganizationMixin
from litestar_auth._tenant_resolution import (
    ClaimTenantResolver,
    HeaderTenantResolver,
    SubdomainTenantResolver,
    TenantResolver,
)
from litestar_auth.authentication.strategy.api_key import ApiKeyContext
from litestar_auth.authentication.strategy.jwt import JWTContext
from litestar_auth.ratelimit._client_host import _get_header_value, _normalize_host_value

pytestmark = pytest.mark.unit

if TYPE_CHECKING:
    from litestar.types import HTTPScope


def _build_connection(
    headers: list[tuple[bytes, bytes]],
    *,
    auth: object | None = None,
) -> ASGIConnection[Any, Any, Any, Any]:
    """Create a minimal ASGI connection carrying request headers.

    Returns:
        ASGI connection carrying the provided raw headers.
    """
    scope = cast(
        "HTTPScope",
        {
            "type": "http",
            "http_version": "1.1",
            "method": "GET",
            "scheme": "https",
            "path": "/",
            "raw_path": b"/",
            "root_path": "",
            "query_string": b"",
            "headers": headers,
            "client": ("127.0.0.1", 12345),
            "server": ("example.com", 443),
            "path_params": {},
        },
    )
    scope["auth"] = auth
    return ASGIConnection(scope=scope)


def _organization_mixin_normalized_slug(raw_slug: str) -> str:
    """Normalize through the same validator used by organization ORM rows.

    Returns:
        The normalized organization slug.
    """
    return OrganizationMixin()._normalize_slug("slug", raw_slug)


def test_tenant_resolver_protocol_accepts_header_resolver() -> None:
    """Concrete resolvers satisfy the typed tenant resolver contract."""
    resolver: TenantResolver = HeaderTenantResolver()

    assert resolver(_build_connection([(b"x-organization", b"Acme")])) == "acme"


def test_header_tenant_resolver_extracts_configured_header_and_normalizes_slug() -> None:
    """Header values normalize with the organization-slug contract."""
    resolver = HeaderTenantResolver(header_name="X-Tenant")
    connection = _build_connection([(b"x-tenant", b" Acme Team ")])

    assert resolver(connection) == _organization_mixin_normalized_slug(" Acme Team ")


def test_claim_tenant_resolver_extracts_verified_jwt_context_and_normalizes_slug() -> None:
    """Signed JWT organization context is the trusted tenant source."""
    connection = _build_connection(
        [(b"x-organization", b"untrusted-header")],
        auth=JWTContext(organization=" Acme Team "),
    )

    assert ClaimTenantResolver()(connection) == _organization_mixin_normalized_slug(" Acme Team ")


@pytest.mark.parametrize(
    "auth",
    [
        pytest.param(None, id="missing"),
        pytest.param(JWTContext(), id="jwt-without-organization"),
        pytest.param(ApiKeyContext(key_id="key-id", scopes=(), prefix_env="prod"), id="non-jwt-context"),
    ],
)
def test_claim_tenant_resolver_returns_none_without_signed_jwt_organization_context(auth: object | None) -> None:
    """Requests without signed JWT organization context fail closed."""
    connection = _build_connection([(b"x-organization", b"acme")], auth=auth)

    assert ClaimTenantResolver()(connection) is None


def test_claim_tenant_resolver_returns_none_for_malformed_jwt_organization_context() -> None:
    """Malformed JWT organization values fail closed after contextual auth."""
    connection = _build_connection([], auth=JWTContext(organization="   "))

    assert ClaimTenantResolver()(connection) is None


@pytest.mark.parametrize(
    "headers",
    [
        pytest.param([], id="missing"),
        pytest.param([(b"x-organization", b"   ")], id="blank"),
    ],
)
def test_header_tenant_resolver_returns_none_when_missing_or_blank(headers: list[tuple[bytes, bytes]]) -> None:
    """Missing or blank tenant headers fail closed."""
    assert HeaderTenantResolver()(_build_connection(headers)) is None


@pytest.mark.parametrize(
    ("host", "expected"),
    [
        pytest.param("Acme.Example.COM", "acme", id="uppercase"),
        pytest.param("Acme.Example.COM:8443", "acme", id="port"),
        pytest.param("xn--bcher-kva.example.com", "bücher", id="idna"),
    ],
)
def test_subdomain_tenant_resolver_derives_slug_from_host_edge_cases(host: str, expected: str) -> None:
    """Subdomain values are parsed through the shared host normalization helper."""
    connection = _build_connection([(b"host", host.encode())])

    assert SubdomainTenantResolver(root_domain="example.com")(connection) == expected


@pytest.mark.parametrize(
    "headers",
    [
        pytest.param([], id="missing-host"),
        pytest.param([(b"host", b"example.com")], id="apex"),
        pytest.param([(b"host", b"other.test")], id="outside-root"),
        pytest.param([(b"host", b"[::1]:8443")], id="ipv6"),
    ],
)
def test_subdomain_tenant_resolver_returns_none_without_subdomain(headers: list[tuple[bytes, bytes]]) -> None:
    """Hosts without a tenant subdomain fail closed."""
    assert SubdomainTenantResolver(root_domain="example.com")(_build_connection(headers)) is None


def test_shared_host_header_lookup_falls_back_to_casefolded_iteration() -> None:
    """Host parsing keeps case-insensitive behavior for plain mappings too."""
    assert _get_header_value({"HOST": "Acme.Example.com"}, "Host") == "Acme.Example.com"
    assert _get_header_value({"CONTENT-TYPE": "application/json"}, "Host") is None


@pytest.mark.parametrize(
    "raw_host",
    [
        pytest.param("", id="blank"),
        pytest.param("[::1", id="bad-ipv6-bracket"),
        pytest.param("...", id="empty-labels"),
        pytest.param("\ud800.example.com", id="invalid-idna"),
    ],
)
def test_shared_host_normalization_returns_none_for_malformed_hosts(raw_host: str) -> None:
    """Malformed host values fail closed instead of raising."""
    assert _normalize_host_value(raw_host) is None


def test_subdomain_tenant_resolver_output_matches_organization_slug_normalization() -> None:
    """Subdomain output uses the OrganizationMixin slug normalization path."""
    connection = _build_connection([(b"host", b" Acme.example.com ")])
    expected_slug = _organization_mixin_normalized_slug("acme")

    assert SubdomainTenantResolver(root_domain="example.com")(connection) == expected_slug
