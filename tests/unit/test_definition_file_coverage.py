"""Reload-based coverage tests for definition-heavy modules."""

from __future__ import annotations

import importlib.machinery
import importlib.util
import sys
import types
import uuid
import warnings
from pathlib import Path
from typing import TYPE_CHECKING, Any, cast, get_args, get_type_hints
from uuid import uuid4

import pytest
from sqlalchemy import Uuid, inspect
from sqlalchemy.exc import SAWarning
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column

import litestar_auth._auth_model_mixins as auth_model_mixins_module
import litestar_auth._manager._protocols as manager_protocols_module
import litestar_auth._roles as roles_module
import litestar_auth.authentication.strategy.base as strategy_base_module
import litestar_auth.authentication.transport.base as transport_base_module
import litestar_auth.db.base as db_base_module
import litestar_auth.models.mixins as model_mixins_module
import litestar_auth.schemas as schemas_module
import litestar_auth.types as types_module
from litestar_auth.authentication.strategy.db_models import AccessToken as ModelsAccessToken
from litestar_auth.authentication.strategy.db_models import RefreshToken as ModelsRefreshToken
from litestar_auth.models.mixins import (
    AccessTokenMixin,
    OAuthAccountMixin,
    RefreshTokenMixin,
    RoleMixin,
    UserAuthRelationshipMixin,
    UserModelMixin,
    UserRoleAssociationMixin,
    UserRoleRelationshipMixin,
)
from litestar_auth.models.oauth import OAuthAccount as ModelsOAuthAccount
from litestar_auth.models.role import Role as ModelsRole
from litestar_auth.models.role import UserRole as ModelsUserRole
from litestar_auth.models.user import User as ModelsUser
from tests._helpers import ExampleUser

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
            del path, target
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


def test_roles_module_preserves_normalized_roles_contract() -> None:
    """The roles helper module still exercises its public normalization surface."""
    assert roles_module.normalize_roles([" Billing ", "admin", "ADMIN"]) == ["admin", "billing"]
    assert roles_module.normalize_roles((" Support ", "ADMIN")) == ["admin", "support"]
    assert roles_module.normalize_roles(None) == []
    assert roles_module.normalize_role_name(" Support ") == "support"


def test_schemas_module_preserves_struct_definitions() -> None:
    """Msgspec schema definitions still expose their fields remain stable."""
    user_read_hints = get_type_hints(schemas_module.UserRead, include_extras=True)
    user_update_hints = get_type_hints(schemas_module.UserUpdate, include_extras=True)

    assert schemas_module.UserRead.__struct_fields__ == (
        "id",
        "email",
        "is_active",
        "is_verified",
        "roles",
    )
    assert schemas_module.UserCreate.__struct_fields__ == ("email", "password")
    assert schemas_module.UserUpdate.__struct_fields__ == (
        "email",
        "is_active",
        "is_verified",
        "roles",
    )
    assert user_read_hints["roles"] == list[str]
    assert get_args(user_update_hints["roles"])[0] == list[str]
    assert get_args(user_update_hints["roles"])[1] is type(None)


def test_strategy_base_module_preserves_abstract_contracts() -> None:
    """Strategy base definitions still exposes the contract surfaces remain exported."""
    assert strategy_base_module.UserManagerProtocol.__name__ == "UserManagerProtocol"
    assert strategy_base_module.Strategy.__abstractmethods__ == {"destroy_token", "read_token", "write_token"}
    assert "with_session" in strategy_base_module.SessionBindable.__dict__
    assert "write_refresh_token" in strategy_base_module.RefreshableStrategy.__dict__
    assert "rotate_refresh_token" in strategy_base_module.RefreshableStrategy.__dict__
    assert "invalidate_all_tokens" in strategy_base_module.TokenInvalidationCapable.__dict__


def test_transport_base_module_preserves_abstract_contracts() -> None:
    """Transport base definitions still exposes the abstract API remains stable."""
    assert transport_base_module.LogoutTokenReadable.__name__ == "LogoutTokenReadable"
    assert transport_base_module.Transport.__abstractmethods__ == {"read_token", "set_login_token", "set_logout"}


def test_db_base_module_preserves_store_contracts() -> None:
    """Persistence contracts still exposes the expected methods remain exposed."""
    assert db_base_module.BaseUserStore.__dict__.keys() >= {
        "create",
        "delete",
        "get",
        "get_by_email",
        "get_by_field",
        "list_users",
        "update",
    }
    assert "get_by_oauth_account" in db_base_module.BaseOAuthAccountStore.__dict__
    assert "upsert_oauth_account" in db_base_module.BaseOAuthAccountStore.__dict__


async def test_db_base_protocol_method_stubs_execute_under_coverage() -> None:
    """Execute protocol stub bodies so coverage records the structural contract surface."""
    dummy_self = cast("Any", object())

    assert await db_base_module.BaseUserStore.get(dummy_self, uuid4()) is None
    assert await db_base_module.BaseUserStore.get_by_email(dummy_self, "user@example.com") is None
    assert await db_base_module.BaseUserStore.get_by_field(dummy_self, "email", "user@example.com") is None
    assert await db_base_module.BaseUserStore.create(dummy_self, {"email": "user@example.com"}) is None
    assert await db_base_module.BaseUserStore.list_users(dummy_self, offset=0, limit=10) is None
    assert await db_base_module.BaseUserStore.update(dummy_self, cast("Any", object()), {"email": "updated"}) is None
    assert await db_base_module.BaseUserStore.delete(dummy_self, uuid4()) is None
    assert await db_base_module.BaseOAuthAccountStore.get_by_oauth_account(dummy_self, "provider", "account") is None
    assert (
        await db_base_module.BaseOAuthAccountStore.upsert_oauth_account(
            dummy_self,
            cast("Any", object()),
            account=db_base_module.OAuthAccountData(
                oauth_name="provider",
                account_id="account",
                account_email="user@example.com",
                access_token="token",
                expires_at=None,
                refresh_token=None,
            ),
        )
        is None
    )


def test_manager_protocols_module_preserves_internal_protocols() -> None:
    """Internal manager protocols still exposes their required attributes remain defined."""
    assert manager_protocols_module.ManagedUserProtocol.__annotations__ == {"email": "str", "hashed_password": "str"}
    assert manager_protocols_module.AccountStateUserProtocol.__name__ == "AccountStateUserProtocol"
    assert manager_protocols_module.UserDatabaseManagerProtocol.__annotations__ == {"user_db": "Any"}


def test_models_mixins_module_preserves_contract_exports() -> None:
    """side-effect-free auth mixin module still exposes its export surface."""
    assert model_mixins_module.__all__ == (
        "AccessTokenMixin",
        "OAuthAccountMixin",
        "RefreshTokenMixin",
        "RoleMixin",
        "UserAuthRelationshipMixin",
        "UserModelMixin",
        "UserRoleAssociationMixin",
        "UserRoleRelationshipMixin",
    )
    assert hasattr(model_mixins_module.UserModelMixin, "email")
    assert hasattr(model_mixins_module.OAuthAccountMixin, "access_token")
    assert hasattr(model_mixins_module.RoleMixin, "name")
    assert hasattr(model_mixins_module.UserRoleRelationshipMixin, "roles")
    assert not hasattr(model_mixins_module, "_TokenModelMixin")
    assert issubclass(ModelsUser, UserModelMixin)
    assert issubclass(ModelsOAuthAccount, OAuthAccountMixin)
    assert issubclass(ModelsRole, RoleMixin)
    assert issubclass(ModelsUserRole, UserRoleAssociationMixin)
    assert issubclass(ModelsAccessToken, AccessTokenMixin)
    assert issubclass(ModelsRefreshToken, RefreshTokenMixin)


def test_internal_auth_model_mixins_module_preserves_contract_exports(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Internal auth mixin module still exposes its reusable contracts stay stable."""
    reloaded_module = _load_reloaded_alias(
        alias_name="_coverage_alias_auth_model_mixins",
        source_path=REPO_ROOT / "litestar_auth" / "_auth_model_mixins.py",
        monkeypatch=monkeypatch,
    )

    assert reloaded_module.__all__ == (
        "AccessTokenMixin",
        "RefreshTokenMixin",
        "RoleMixin",
        "UserAuthRelationshipMixin",
        "UserModelMixin",
        "UserRoleAssociationMixin",
        "UserRoleRelationshipMixin",
        "_TokenModelMixin",
    )
    assert reloaded_module._USER_RELATIONSHIP_NAME == "user"
    assert reloaded_module._ROLE_ASSIGNMENTS_RELATIONSHIP_NAME == "role_assignments"
    assert sorted(reloaded_module.UserModelMixin.__annotations__) == [
        "email",
        "hashed_password",
        "is_active",
        "is_verified",
        "recovery_codes",
        "totp_secret",
    ]
    assert reloaded_module.UserRoleRelationshipMixin.auth_user_role_model == "UserRole"
    assert reloaded_module.RoleMixin.auth_user_role_model == "UserRole"
    assert reloaded_module.UserRoleAssociationMixin.auth_role_model == "Role"
    assert reloaded_module.AccessTokenMixin.auth_user_back_populates == "access_tokens"
    assert reloaded_module.RefreshTokenMixin.auth_user_back_populates == "refresh_tokens"
    assert reloaded_module.AccessTokenMixin.__mro__[1].__name__ == "_TokenModelMixin"
    assert reloaded_module.RefreshTokenMixin.__mro__[1].__name__ == "_TokenModelMixin"
    assert reloaded_module._TokenModelMixin.__annotations__["user_id"] == "Mapped[uuid.UUID]"
    assert reloaded_module._TokenModelMixin.__annotations__["user"] == "Mapped[Any]"


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


def test_models_user_module_columns_and_relationships() -> None:
    """Reference ``User`` model keeps relational role tables behind a flat roles property."""
    user_relationships = inspect(ModelsUser).relationships

    assert issubclass(ModelsUser, UserModelMixin)
    assert issubclass(ModelsUser, UserRoleRelationshipMixin)
    assert issubclass(ModelsUser, UserAuthRelationshipMixin)
    assert issubclass(ModelsRole, RoleMixin)
    assert issubclass(ModelsUserRole, UserRoleAssociationMixin)
    assert issubclass(ModelsOAuthAccount, OAuthAccountMixin)
    assert issubclass(ModelsAccessToken, AccessTokenMixin)
    assert issubclass(ModelsRefreshToken, RefreshTokenMixin)
    assert ModelsUser.__tablename__ == "user"
    assert set(ModelsUser.__table__.c.keys()) <= {
        "email",
        "hashed_password",
        "id",
        "is_active",
        "is_verified",
        "recovery_codes",
        "sa_orm_sentinel",
        "totp_secret",
    }
    assert "roles" not in ModelsUser.__table__.c
    assert sorted(UserModelMixin.__annotations__) == [
        "email",
        "hashed_password",
        "is_active",
        "is_verified",
        "recovery_codes",
        "totp_secret",
    ]
    assert set(ModelsRole.__table__.c.keys()) == {"description", "name"}
    assert ModelsRole.__table__.c.description.nullable is True
    assert set(ModelsUserRole.__table__.c.keys()) == {"role_name", "user_id"}
    assert sorted(user_relationships.keys()) == [
        "access_tokens",
        "oauth_accounts",
        "refresh_tokens",
        "role_assignments",
    ]
    assert user_relationships["access_tokens"].mapper.class_.__name__ == "AccessToken"
    assert user_relationships["access_tokens"].back_populates == "user"
    assert user_relationships["refresh_tokens"].mapper.class_.__name__ == "RefreshToken"
    assert user_relationships["refresh_tokens"].back_populates == "user"
    assert user_relationships["oauth_accounts"].mapper.class_.__name__ == "OAuthAccount"
    assert user_relationships["oauth_accounts"].back_populates == "user"
    assert user_relationships["role_assignments"].mapper.class_.__name__ == "UserRole"
    assert user_relationships["role_assignments"].back_populates == "user"
    assert inspect(ModelsUserRole).relationships["role"].mapper.class_ is ModelsRole
    assert inspect(ModelsRole).relationships["user_assignments"].mapper.class_ is ModelsUserRole
