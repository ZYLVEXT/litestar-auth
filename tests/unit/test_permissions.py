"""Tests for permission normalization and wildcard matching."""

from __future__ import annotations

from types import SimpleNamespace
from typing import TYPE_CHECKING

import pytest

from litestar_auth._permissions import (
    GLOBAL_PERMISSION_GRANT,
    StaticRolePermissionResolver,
    normalize_permission_name,
    normalize_permissions,
    permission_grants,
    permission_grants_fixed_work,
    permissions_cover_delegated_grant,
    permissions_grant,
)
from litestar_auth._roles import normalize_role_name, normalize_roles

if TYPE_CHECKING:
    from litestar_auth.types import PermissionResolver

pytestmark = pytest.mark.unit


def test_permission_normalization_matches_role_scope_normalization() -> None:
    """Permissions and API-key scopes share one canonical string form."""
    raw_permissions = (" Posts:Read ", "posts:read", "Users:Write")

    assert normalize_permissions(raw_permissions) == normalize_roles(raw_permissions)
    assert normalize_permission_name(" Posts:Read ") == normalize_role_name(" Posts:Read ")


def test_normalize_permissions_deduplicates_and_sorts_tokens() -> None:
    """Permission collections use deterministic role-style ordering."""
    assert normalize_permissions(("users:write", " Posts:Read ", "posts:read", "posts:*", "*")) == [
        "*",
        "posts:*",
        "posts:read",
        "users:write",
    ]


@pytest.mark.parametrize(
    "raw_permissions",
    [
        pytest.param(("posts",), id="missing-separator"),
        pytest.param(("posts:",), id="missing-action"),
        pytest.param((":read",), id="missing-resource"),
        pytest.param(("posts:read:own",), id="too-many-separators"),
        pytest.param((" ",), id="empty-after-normalization"),
    ],
)
def test_normalize_permissions_rejects_invalid_tokens(raw_permissions: tuple[str, ...]) -> None:
    """Permission tokens are either global wildcard or resource/action pairs."""
    with pytest.raises(ValueError, match=r"Permissions|Roles"):
        normalize_permissions(raw_permissions)


@pytest.mark.parametrize(
    ("granted_permission", "required_permission"),
    [
        pytest.param("posts:read", "posts:read", id="exact"),
        pytest.param(" Posts:Read ", "posts:read", id="normalized-exact"),
        pytest.param("posts:*", "posts:read", id="resource-wildcard"),
        pytest.param("*", "posts:read", id="global-wildcard"),
    ],
)
def test_permission_grants_allowed_cases(granted_permission: str, required_permission: str) -> None:
    """Granted-side exact and wildcard tokens satisfy matching requirements."""
    assert permission_grants(granted_permission, required_permission)


@pytest.mark.parametrize(
    ("granted_permission", "required_permission"),
    [
        pytest.param("posts:read", "posts:write", id="cross-action"),
        pytest.param("posts:*", "users:read", id="cross-resource"),
        pytest.param("posts:read", "posts:*", id="required-resource-wildcard"),
        pytest.param("*", "*", id="required-global-wildcard"),
        pytest.param("users:*", "posts:*", id="required-wildcard-cross-resource"),
    ],
)
def test_permission_grants_denied_cases(granted_permission: str, required_permission: str) -> None:
    """Required-side wildcard tokens are not usable permission requirements."""
    assert not permission_grants(granted_permission, required_permission)


def test_permissions_grant_checks_normalized_collection() -> None:
    """A permission collection grants access when any token satisfies the requirement."""
    assert permissions_grant(("users:read", " Posts:* "), "posts:write")
    assert not permissions_grant(("users:read", "posts:read"), "posts:write")
    assert not permissions_grant(("*",), "*")


@pytest.mark.parametrize(
    ("granted_permissions", "required_permission", "expected"),
    [
        pytest.param(frozenset({"posts:read"}), "posts:read", True, id="exact"),
        pytest.param(frozenset({"posts:*"}), "posts:read", True, id="resource-wildcard"),
        pytest.param(frozenset({"*"}), "posts:read", True, id="global-wildcard"),
        pytest.param(frozenset({"users:read", "posts:*"}), "posts:write", True, id="any-of-many"),
        pytest.param(frozenset({"posts:read"}), "posts:write", False, id="cross-action"),
        pytest.param(frozenset({"posts:*"}), "users:read", False, id="cross-resource"),
        pytest.param(frozenset(), "posts:read", False, id="empty-grants"),
        pytest.param(frozenset({"posts:*"}), "posts:*", False, id="required-resource-wildcard"),
        pytest.param(frozenset({"*"}), "*", False, id="required-global-wildcard"),
    ],
)
def test_permission_grants_fixed_work_matches_short_circuit_matcher(
    granted_permissions: frozenset[str],
    required_permission: str,
    *,
    expected: bool,
) -> None:
    """The constant-work matcher agrees with permissions_grant on normalized inputs."""
    assert permission_grants_fixed_work(granted_permissions, required_permission) is expected
    assert permissions_grant(granted_permissions, required_permission) is expected


@pytest.mark.parametrize(
    ("granted_permissions", "required_permission", "expected"),
    [
        pytest.param(frozenset({"café:read"}), "café:read", True, id="non-ascii-exact"),
        pytest.param(frozenset({"café:*"}), "café:read", True, id="non-ascii-resource-wildcard"),
        pytest.param(frozenset({"café:read"}), "café:write", False, id="non-ascii-cross-action"),
        pytest.param(frozenset({"статья:читать"}), "статья:читать", True, id="cyrillic-exact"),
    ],
)
def test_permission_grants_fixed_work_supports_non_ascii_tokens(
    granted_permissions: frozenset[str],
    required_permission: str,
    *,
    expected: bool,
) -> None:
    """Constant-work matching must not crash on non-ASCII permission tokens.

    ``hmac.compare_digest`` rejects non-ASCII ``str`` operands; the matcher compares
    UTF-8 bytes so NFKC-normalized non-ASCII tokens still resolve instead of raising.
    """
    assert permission_grants_fixed_work(granted_permissions, required_permission) is expected
    assert permissions_grant(granted_permissions, required_permission) is expected


@pytest.mark.parametrize(
    ("granted_permissions", "delegated_permission", "expected"),
    [
        pytest.param(("posts:*",), "posts:read", True, id="owner-wildcard-covers-specific"),
        pytest.param(("posts:*",), "posts:*", True, id="owner-wildcard-covers-same-wildcard"),
        pytest.param(("*",), "posts:*", True, id="owner-global-covers-resource-wildcard"),
        pytest.param(("*",), "*", True, id="owner-global-covers-global"),
        pytest.param(("posts:read",), "posts:*", False, id="specific-does-not-cover-resource-wildcard"),
        pytest.param(("posts:*",), "*", False, id="resource-wildcard-does-not-cover-global"),
        pytest.param(("users:*",), "posts:read", False, id="cross-resource-denied"),
    ],
)
def test_permissions_cover_delegated_grant_for_api_key_scope_downscoping(
    granted_permissions: tuple[str, ...],
    delegated_permission: str,
    *,
    expected: bool,
) -> None:
    """Delegated API-key wildcard grants require owner grants at least as broad."""
    assert permissions_cover_delegated_grant(granted_permissions, delegated_permission) is expected


def test_static_role_permission_resolver_expands_multiple_roles() -> None:
    """Mapped role permissions resolve to a normalized deduplicated union."""
    resolver: PermissionResolver = StaticRolePermissionResolver(
        {
            " Admin ": ("Posts:Read", "users:write"),
            "editor": ("posts:write", "posts:read"),
        },
    )
    user = SimpleNamespace(roles=["editor", "admin"])

    assert resolver.resolve(user) == frozenset({"posts:read", "posts:write", "users:write"})


def test_static_role_permission_resolver_treats_configured_superuser_as_global_grant() -> None:
    """The configured superuser role resolves to the global permission grant."""
    resolver = StaticRolePermissionResolver(
        {"member": ("posts:read",)},
        superuser_role_name=" Owner ",
    )
    permissions = resolver.resolve(SimpleNamespace(roles=["owner"]))

    assert permissions == frozenset({GLOBAL_PERMISSION_GRANT})
    assert permissions_grant(permissions, "tenants:delete")


def test_static_role_permission_resolver_ignores_context_argument() -> None:
    """The reserved context argument does not affect static role resolution."""
    resolver = StaticRolePermissionResolver({"member": ("posts:read",)})
    user = SimpleNamespace(roles=["member"])

    assert resolver.resolve(user, context={"tenant_id": "tenant-1"}) == resolver.resolve(user)


def test_static_role_permission_resolver_unknown_and_empty_roles_resolve_empty() -> None:
    """Unknown role names and empty membership do not grant permissions."""
    resolver = StaticRolePermissionResolver({"member": ("posts:read",)})

    assert resolver.resolve(SimpleNamespace(roles=["missing"])) == frozenset()
    assert resolver.resolve(SimpleNamespace(roles=[])) == frozenset()
    assert resolver.resolve(SimpleNamespace()) == frozenset()


def test_role_normalization_behavior_remains_unchanged() -> None:
    """Existing role normalization still trims, lowercases, deduplicates, and sorts."""
    assert normalize_roles((" Admin ", "admin", "billing")) == ["admin", "billing"]
    assert normalize_role_name(" Admin ") == "admin"
