"""Reload-based coverage tests for definition-heavy modules."""

from __future__ import annotations

import importlib.machinery
import importlib.util
import sys
import types
import uuid
import warnings
from pathlib import Path
from typing import TYPE_CHECKING, get_args, get_type_hints

import pytest
from sqlalchemy import Uuid, inspect
from sqlalchemy.exc import SAWarning
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column

import litestar_auth._auth_model_mixins as auth_model_mixins_module
import litestar_auth._manager._protocols as manager_protocols_module
import litestar_auth._plugin._protocols as plugin_protocols_module
import litestar_auth._plugin.security_policy as security_policy_module
import litestar_auth._roles as roles_module
import litestar_auth.authentication.strategy.base as strategy_base_module
import litestar_auth.authentication.transport.base as transport_base_module
import litestar_auth.controllers._step_up_payloads as step_up_payloads_module
import litestar_auth.models.mixins as model_mixins_module
import litestar_auth.payloads as payloads_module
import litestar_auth.schemas as schemas_module
import litestar_auth.types as types_module
from tests._helpers import ExampleUser

uuid4 = uuid.uuid4
AccessTokenMixin = model_mixins_module.AccessTokenMixin
OAuthAccountMixin = model_mixins_module.OAuthAccountMixin
OrganizationInvitationMixin = model_mixins_module.OrganizationInvitationMixin
OrganizationMembershipMixin = model_mixins_module.OrganizationMembershipMixin
OrganizationMixin = model_mixins_module.OrganizationMixin
RefreshTokenMixin = model_mixins_module.RefreshTokenMixin
RoleMixin = model_mixins_module.RoleMixin
UserAuthRelationshipMixin = model_mixins_module.UserAuthRelationshipMixin
UserModelMixin = model_mixins_module.UserModelMixin
UserRoleAssociationMixin = model_mixins_module.UserRoleAssociationMixin
UserRoleRelationshipMixin = model_mixins_module.UserRoleRelationshipMixin

if TYPE_CHECKING:
    from collections.abc import Callable
    from types import ModuleType

pytestmark = [pytest.mark.unit, pytest.mark.imports]
REPO_ROOT = Path(__file__).resolve().parents[2]


def load_reloaded_test_alias(
    *,
    alias_name: str,
    source_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    after_exec: Callable[[ModuleType], None] | None = None,
) -> ModuleType:
    """Load and reload a source file under an isolated alias for coverage tests.

    Returns:
        The reloaded alias module.
    """

    class _AliasFinder:
        """Meta path finder that makes the reload alias discoverable."""

        def find_spec(
            self,
            fullname: str,
            path: object,
            target: object = None,
        ) -> importlib.machinery.ModuleSpec | None:
            if fullname != alias_name:
                return None
            return importlib.util.spec_from_file_location(alias_name, source_path)

    spec = importlib.util.spec_from_file_location(alias_name, source_path)
    assert spec is not None
    assert spec.loader is not None

    alias_module = importlib.util.module_from_spec(spec)
    monkeypatch.setattr(sys, "meta_path", [_AliasFinder(), *sys.meta_path])
    monkeypatch.setitem(sys.modules, alias_name, alias_module)
    spec.loader.exec_module(alias_module)
    if after_exec is not None:
        after_exec(alias_module)
    return alias_module


def _load_reloaded_alias(
    *,
    alias_name: str,
    source_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> ModuleType:
    """Load a source file under an isolated module name and reload it.

    Returns:
        The reloaded alias module.
    """

    class _AliasBase(DeclarativeBase):
        """Declarative base dedicated to reload-only coverage tests."""

    class UUIDBase(_AliasBase):
        """Minimal UUID base compatible with the model definitions."""

        __abstract__ = True

        id: Mapped[uuid.UUID] = mapped_column(Uuid, primary_key=True, default=uuid4)

    class DefaultBase(_AliasBase):
        """Minimal default base for token model definitions."""

        __abstract__ = True

    fake_base_module = types.ModuleType("advanced_alchemy.base")
    fake_base_namespace = fake_base_module.__dict__
    fake_base_namespace["UUIDBase"] = UUIDBase
    fake_base_namespace["DefaultBase"] = DefaultBase

    monkeypatch.setitem(sys.modules, "advanced_alchemy.base", fake_base_module)

    def _remove_declared_tables(alias_module: ModuleType) -> None:
        """Clear declared tables so the alias can be reloaded safely."""
        for value in alias_module.__dict__.values():
            table = getattr(value, "__table__", None)
            if table is not None and table.key in table.metadata.tables:
                table.metadata.remove(table)

    with warnings.catch_warnings():
        warnings.simplefilter("ignore", category=SAWarning)
        return load_reloaded_test_alias(
            alias_name=alias_name,
            source_path=source_path,
            monkeypatch=monkeypatch,
            after_exec=_remove_declared_tables,
        )


@pytest.mark.parametrize(
    ("module_name", "export_name"),
    [
        ("_totp_primitive", "verify_totp"),
        ("_totp_recovery", "generate_totp_recovery_codes"),
        ("_totp_stores", "InMemoryTotpEnrollmentStore"),
        ("_totp_verify", "verify_totp_with_store"),
    ],
)
def test_totp_definition_modules_load_under_coverage(
    module_name: str,
    export_name: str,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """TOTP modules remain importable when coverage starts after plugin discovery."""
    module = load_reloaded_test_alias(
        alias_name=f"litestar_auth._coverage_{module_name.removeprefix('_')}",
        source_path=REPO_ROOT / "litestar_auth" / f"{module_name}.py",
        monkeypatch=monkeypatch,
    )

    assert hasattr(module, export_name)


def test_plugin_security_policy_inventory_is_stable() -> None:
    """The plugin exposes its single managed TOTP storage policy."""
    policies = security_policy_module._iter_plugin_security_policies()

    assert len(policies) == 1
    assert policies[0].key == "totp_secret_storage"


def test_types_module_preserves_protocol_exports() -> None:
    """Shared typing module still exposes its public protocols remain usable."""

    class _RoleCapableUser:
        id = uuid4()
        roles = ("admin",)

    assert types_module.UserProtocol.__name__ == "UserProtocol"
    assert types_module.GuardedUserProtocol.__name__ == "GuardedUserProtocol"
    assert types_module.RoleCapableUserProtocol.__name__ == "RoleCapableUserProtocol"
    assert types_module.TotpUserProtocol.__name__ == "TotpUserProtocol"
    assert types_module.TransportProtocol.__name__ == "TransportProtocol"
    assert types_module.StrategyProtocol.__name__ == "StrategyProtocol"
    assert get_args(types_module.LoginIdentifier.__value__) == ("email", "username")
    assert isinstance(ExampleUser(id=uuid4()), types_module.GuardedUserProtocol)
    assert isinstance(_RoleCapableUser(), types_module.RoleCapableUserProtocol)


def test_plugin_protocol_module_preserves_private_contract_names() -> None:
    """Plugin assembly protocol names remain importable for type-only boundaries."""
    assert plugin_protocols_module.StrategyProto.__name__ == "StrategyProto"
    assert plugin_protocols_module.AuthBackendProto.__name__ == "AuthBackendProto"
    assert plugin_protocols_module.RouteHandlerWithHandlers.__name__ == "RouteHandlerWithHandlers"
    assert plugin_protocols_module.DependencyProvider.__name__ == "DependencyProvider"


def test_roles_module_preserves_normalized_roles_contract() -> None:
    """The roles helper module still exercises its public normalization surface."""
    assert roles_module.normalize_roles([" Billing ", "admin", "ADMIN"]) == ["admin", "billing"]
    assert roles_module.normalize_roles((" Support ", "ADMIN")) == ["admin", "support"]
    assert roles_module.normalize_roles(None) == []
    assert roles_module.normalize_role_name(" Support ") == "support"


def test_schemas_module_preserves_struct_definitions() -> None:
    """Msgspec schema definitions still expose their fields remain stable.

    Privileged fields live exclusively on AdminUserUpdate; the self-service
    UserUpdate carries only email plus current-password proof so a forgotten
    field on the runtime deny-list cannot escalate self-update into a
    privilege change.
    """
    user_read_hints = get_type_hints(schemas_module.UserRead, include_extras=True)
    admin_update_hints = get_type_hints(schemas_module.AdminUserUpdate, include_extras=True)

    assert schemas_module.UserRead.__struct_fields__ == (
        "id",
        "email",
        "is_active",
        "is_verified",
        "roles",
    )
    assert schemas_module.UserCreate.__struct_fields__ == ("email", "password")
    assert schemas_module.UserUpdate.__struct_fields__ == ("email", "current_password", "totp_code")
    assert schemas_module.AdminUserUpdate.__struct_fields__ == (
        "password",
        "email",
        "is_active",
        "is_verified",
        "roles",
        "current_password",
        "totp_code",
    )
    assert user_read_hints["roles"] == list[str]
    assert get_args(admin_update_hints["roles"])[0] == list[str]
    assert get_args(admin_update_hints["roles"])[1] is type(None)


def test_admin_step_up_payload_field_contract() -> None:
    """Admin step-up request body preserves its (current_password, totp_code) field contract."""
    assert step_up_payloads_module.AdminUserDeleteStepUpRequest.__struct_fields__ == ("current_password", "totp_code")
    assert (
        step_up_payloads_module.AdminUserDeleteStepUpRequest.__mro__[1]
        is step_up_payloads_module._AdminCurrentPasswordStepUpRequest
    )
    assert step_up_payloads_module._AdminCurrentPasswordStepUpRequest.__struct_fields__ == ("current_password",)


def test_payloads_module_preserves_refresh_session_response_contract() -> None:
    """Session/device response payloads expose only safe public refresh-session data."""
    session_hints = get_type_hints(payloads_module.RefreshSessionRead, include_extras=True)

    assert payloads_module.RefreshSessionRead.__struct_fields__ == (
        "session_id",
        "created_at",
        "last_used_at",
        "is_current",
        "client_metadata",
    )
    assert payloads_module.RefreshSessionListResponse.__struct_fields__ == ("sessions",)
    assert session_hints["session_id"] is str
    assert get_args(session_hints["last_used_at"])[1] is type(None)
    assert get_args(session_hints["is_current"])[1] is type(None)
    assert get_args(session_hints["client_metadata"])[1] is type(None)


def test_strategy_base_module_preserves_abstract_contracts() -> None:
    """Strategy base definitions still exposes the contract surfaces remain exported."""
    assert strategy_base_module.UserManagerProtocol.__name__ == "UserManagerProtocol"
    assert strategy_base_module.Strategy.__abstractmethods__ == {"destroy_token", "write_token"}
    assert "with_session" in strategy_base_module.SessionBindable.__dict__
    assert "write_refresh_token" in strategy_base_module.RefreshableStrategy.__dict__
    assert "rotate_refresh_token" in strategy_base_module.RefreshableStrategy.__dict__
    assert "invalidate_all_tokens" in strategy_base_module.TokenInvalidationCapable.__dict__


def test_transport_base_module_preserves_abstract_contracts() -> None:
    """Transport base definitions still exposes the abstract API remains stable."""
    assert transport_base_module.LogoutTokenReadable.__name__ == "LogoutTokenReadable"
    assert transport_base_module.Transport.__abstractmethods__ == {"read_token", "set_login_token", "set_logout"}


def test_manager_protocols_module_preserves_internal_protocols() -> None:
    """Internal manager protocols still exposes their required attributes remain defined."""
    assert manager_protocols_module.ManagedUserProtocol.__annotations__ == {"email": "str", "hashed_password": "str"}
    assert manager_protocols_module.AccountStateUserProtocol.__name__ == "AccountStateUserProtocol"
    assert manager_protocols_module.UserDatabaseManagerProtocol.__annotations__ == {"user_db": "Any"}


def test_auth_model_mixins_cover_full_and_partial_relationship_contracts() -> None:
    """Internal and public auth mixins support both fully wired and intentionally partial model families."""

    class FullCoverageBase(DeclarativeBase):
        """Declarative registry for full-relationship mixin coverage."""

    class FullCoverageUUIDBase(FullCoverageBase):
        """UUID primary-key base for full-relationship mixin coverage."""

        __abstract__ = True

        id: Mapped[uuid.UUID] = mapped_column(Uuid, primary_key=True, default=uuid4)

    class FullCoverageUser(
        auth_model_mixins_module.UserModelMixin,
        auth_model_mixins_module.UserAuthRelationshipMixin,
        FullCoverageUUIDBase,
    ):
        """User model that composes every supported auth relationship branch."""

        __tablename__ = "coverage_full_user"

        auth_access_token_model = "FullCoverageAccessToken"
        auth_refresh_token_model = "FullCoverageRefreshToken"
        auth_oauth_account_model = "FullCoverageOAuthAccount"

    class FullCoverageAccessToken(auth_model_mixins_module.AccessTokenMixin, FullCoverageBase):
        """Access-token model bound to the full coverage user."""

        __tablename__ = "coverage_full_access_token"

        auth_user_model = "FullCoverageUser"
        auth_user_table = "coverage_full_user"

    class FullCoverageRefreshToken(auth_model_mixins_module.RefreshTokenMixin, FullCoverageBase):
        """Refresh-token model bound to the full coverage user."""

        __tablename__ = "coverage_full_refresh_token"

        auth_user_model = "FullCoverageUser"
        auth_user_table = "coverage_full_user"

    class FullCoverageOAuthAccount(OAuthAccountMixin, FullCoverageUUIDBase):
        """OAuth-account model bound to the full coverage user."""

        __tablename__ = "coverage_full_oauth_account"

        auth_user_model = "FullCoverageUser"
        auth_user_table = "coverage_full_user"
        auth_provider_identity_constraint_name = "uq_coverage_full_oauth_identity"

    full_relationships = inspect(FullCoverageUser).relationships

    assert sorted(full_relationships.keys()) == ["access_tokens", "oauth_accounts", "refresh_tokens"]
    assert full_relationships["access_tokens"].mapper.class_ is FullCoverageAccessToken
    assert full_relationships["access_tokens"].lazy == "select"
    assert full_relationships["access_tokens"]._user_defined_foreign_keys == set()
    assert full_relationships["refresh_tokens"].mapper.class_ is FullCoverageRefreshToken
    assert full_relationships["refresh_tokens"].lazy == "select"
    assert full_relationships["refresh_tokens"]._user_defined_foreign_keys == set()
    assert full_relationships["oauth_accounts"].mapper.class_ is FullCoverageOAuthAccount
    assert full_relationships["oauth_accounts"].lazy == "select"
    assert full_relationships["oauth_accounts"]._user_defined_foreign_keys == set()
    assert inspect(FullCoverageAccessToken).relationships["user"].back_populates == "access_tokens"
    assert inspect(FullCoverageRefreshToken).relationships["user"].back_populates == "refresh_tokens"
    assert inspect(FullCoverageOAuthAccount).relationships["user"].back_populates == "oauth_accounts"
    assert (
        next(iter(FullCoverageAccessToken.__table__.c.user_id.foreign_keys)).target_fullname == "coverage_full_user.id"
    )
    assert (
        next(iter(FullCoverageRefreshToken.__table__.c.user_id.foreign_keys)).target_fullname == "coverage_full_user.id"
    )
    assert next(iter(FullCoverageOAuthAccount.__table__.c.user_id.foreign_keys)).target_fullname == (
        "coverage_full_user.id"
    )
    assert {
        constraint.name for constraint in FullCoverageOAuthAccount.__table__.constraints if constraint.name is not None
    } == {"uq_coverage_full_oauth_identity"}

    class PartialCoverageBase(DeclarativeBase):
        """Declarative registry for partial-relationship mixin coverage."""

    class PartialCoverageUUIDBase(PartialCoverageBase):
        """UUID primary-key base for partial-relationship mixin coverage."""

        __abstract__ = True

        id: Mapped[uuid.UUID] = mapped_column(Uuid, primary_key=True, default=uuid4)

    class PartialCoverageUser(
        auth_model_mixins_module.UserModelMixin,
        auth_model_mixins_module.UserAuthRelationshipMixin,
        PartialCoverageUUIDBase,
    ):
        """User model that intentionally disables every optional auth relationship."""

        __tablename__ = "coverage_partial_user"

        auth_access_token_model = None
        auth_refresh_token_model = None
        auth_oauth_account_model = None

    partial_relationships = inspect(PartialCoverageUser).relationships

    assert PartialCoverageUser.access_tokens is None
    assert PartialCoverageUser.refresh_tokens is None
    assert PartialCoverageUser.oauth_accounts is None
    assert list(partial_relationships.keys()) == []


def test_auth_model_mixins_cover_relationship_option_override_contracts() -> None:
    """Internal auth mixins support relationship-option overrides while preserving mapper wiring."""

    class ConfiguredCoverageBase(DeclarativeBase):
        """Declarative registry for relationship-option override coverage."""

    class ConfiguredCoverageUUIDBase(ConfiguredCoverageBase):
        """UUID primary-key base for relationship-option override coverage."""

        __abstract__ = True

        id: Mapped[uuid.UUID] = mapped_column(Uuid, primary_key=True, default=uuid4)

    class ConfiguredCoverageUser(
        auth_model_mixins_module.UserModelMixin,
        auth_model_mixins_module.UserAuthRelationshipMixin,
        ConfiguredCoverageUUIDBase,
    ):
        """User model that overrides supported relationship options through class hooks."""

        __tablename__ = "coverage_configured_user"

        auth_access_token_model = "ConfiguredCoverageAccessToken"
        auth_refresh_token_model = "ConfiguredCoverageRefreshToken"
        auth_oauth_account_model = "ConfiguredCoverageOAuthAccount"
        auth_token_relationship_lazy = "noload"
        auth_oauth_account_relationship_lazy = "selectin"
        auth_oauth_account_relationship_foreign_keys = "ConfiguredCoverageOAuthAccount.user_id"

    class ConfiguredCoverageAccessToken(auth_model_mixins_module.AccessTokenMixin, ConfiguredCoverageBase):
        """Access-token model bound to the configured-relationship coverage user."""

        __tablename__ = "coverage_configured_access_token"

        auth_user_model = "ConfiguredCoverageUser"
        auth_user_table = "coverage_configured_user"

    class ConfiguredCoverageRefreshToken(auth_model_mixins_module.RefreshTokenMixin, ConfiguredCoverageBase):
        """Refresh-token model bound to the configured-relationship coverage user."""

        __tablename__ = "coverage_configured_refresh_token"

        auth_user_model = "ConfiguredCoverageUser"
        auth_user_table = "coverage_configured_user"

    class ConfiguredCoverageOAuthAccount(OAuthAccountMixin, ConfiguredCoverageUUIDBase):
        """OAuth-account model bound to the configured-relationship coverage user."""

        __tablename__ = "coverage_configured_oauth_account"

        auth_user_model = "ConfiguredCoverageUser"
        auth_user_table = "coverage_configured_user"
        auth_provider_identity_constraint_name = "uq_coverage_configured_oauth_identity"

    configured_relationships = inspect(ConfiguredCoverageUser).relationships

    assert sorted(configured_relationships.keys()) == ["access_tokens", "oauth_accounts", "refresh_tokens"]
    assert configured_relationships["access_tokens"].mapper.class_ is ConfiguredCoverageAccessToken
    assert configured_relationships["access_tokens"].lazy == "noload"
    assert configured_relationships["access_tokens"]._user_defined_foreign_keys == set()
    assert configured_relationships["refresh_tokens"].mapper.class_ is ConfiguredCoverageRefreshToken
    assert configured_relationships["refresh_tokens"].lazy == "noload"
    assert configured_relationships["refresh_tokens"]._user_defined_foreign_keys == set()
    assert configured_relationships["oauth_accounts"].mapper.class_ is ConfiguredCoverageOAuthAccount
    assert configured_relationships["oauth_accounts"].lazy == "selectin"
    assert configured_relationships["oauth_accounts"]._user_defined_foreign_keys == {
        ConfiguredCoverageOAuthAccount.__table__.c.user_id,
    }
    assert inspect(ConfiguredCoverageAccessToken).relationships["user"].back_populates == "access_tokens"
    assert inspect(ConfiguredCoverageRefreshToken).relationships["user"].back_populates == "refresh_tokens"
    assert inspect(ConfiguredCoverageOAuthAccount).relationships["user"].back_populates == "oauth_accounts"
    assert (
        next(iter(ConfiguredCoverageAccessToken.__table__.c.user_id.foreign_keys)).target_fullname
        == "coverage_configured_user.id"
    )
    assert (
        next(iter(ConfiguredCoverageRefreshToken.__table__.c.user_id.foreign_keys)).target_fullname
        == "coverage_configured_user.id"
    )
    assert next(iter(ConfiguredCoverageOAuthAccount.__table__.c.user_id.foreign_keys)).target_fullname == (
        "coverage_configured_user.id"
    )
    assert {
        constraint.name
        for constraint in ConfiguredCoverageOAuthAccount.__table__.constraints
        if constraint.name is not None
    } == {"uq_coverage_configured_oauth_identity"}
