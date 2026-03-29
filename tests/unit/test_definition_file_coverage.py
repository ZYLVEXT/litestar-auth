"""Reload-based coverage tests for definition-heavy modules."""

from __future__ import annotations

import importlib
import importlib.machinery
import importlib.util
import sys
import types
import uuid
import warnings
from pathlib import Path
from typing import TYPE_CHECKING, get_args
from uuid import uuid4

import pytest
from sqlalchemy import Uuid
from sqlalchemy.exc import SAWarning
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column

import litestar_auth._manager._protocols as manager_protocols_module
import litestar_auth.authentication.strategy.base as strategy_base_module
import litestar_auth.authentication.transport.base as transport_base_module
import litestar_auth.db.base as db_base_module
import litestar_auth.schemas as schemas_module
import litestar_auth.types as types_module
from tests._helpers import ExampleUser

if TYPE_CHECKING:
    from types import ModuleType

pytestmark = [pytest.mark.unit, pytest.mark.imports]
REPO_ROOT = Path(__file__).resolve().parents[2]


def _reload_module(module: ModuleType) -> ModuleType:
    """Reload a module so coverage records its module body.

    Returns:
        The reloaded module object.
    """
    reloaded_module = importlib.reload(module)

    assert reloaded_module is module
    return reloaded_module


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

    monkeypatch.setattr(sys, "meta_path", [_AliasFinder(), *sys.meta_path])
    monkeypatch.setitem(sys.modules, "advanced_alchemy.base", fake_base_module)

    spec = importlib.util.spec_from_file_location(alias_name, source_path)
    assert spec is not None
    assert spec.loader is not None

    alias_module = importlib.util.module_from_spec(spec)
    monkeypatch.setitem(sys.modules, alias_name, alias_module)
    with warnings.catch_warnings():
        warnings.simplefilter("ignore", category=SAWarning)
        spec.loader.exec_module(alias_module)
        for value in alias_module.__dict__.values():
            table = getattr(value, "__table__", None)
            if table is not None and table.key in table.metadata.tables:
                table.metadata.remove(table)
        return _reload_module(alias_module)


def test_types_module_reload_preserves_protocol_exports() -> None:
    """Reload the shared typing module and verify its public protocols remain usable."""
    reloaded_module = _reload_module(types_module)

    assert reloaded_module.UserProtocol.__name__ == "UserProtocol"
    assert reloaded_module.GuardedUserProtocol.__name__ == "GuardedUserProtocol"
    assert reloaded_module.TotpUserProtocol.__name__ == "TotpUserProtocol"
    assert reloaded_module.TransportProtocol.__name__ == "TransportProtocol"
    assert reloaded_module.StrategyProtocol.__name__ == "StrategyProtocol"
    assert get_args(reloaded_module.LoginIdentifier.__value__) == ("email", "username")
    assert isinstance(ExampleUser(id=uuid4()), reloaded_module.GuardedUserProtocol)


def test_schemas_module_reload_preserves_struct_definitions() -> None:
    """Reload msgspec schema definitions and verify their fields remain stable."""
    reloaded_module = _reload_module(schemas_module)

    assert reloaded_module.UserRead.__struct_fields__ == (
        "id",
        "email",
        "is_active",
        "is_verified",
        "is_superuser",
    )
    assert reloaded_module.UserCreate.__struct_fields__ == ("email", "password")
    assert reloaded_module.UserUpdate.__struct_fields__ == (
        "password",
        "email",
        "is_active",
        "is_verified",
        "is_superuser",
    )


def test_strategy_base_module_reload_preserves_abstract_contracts() -> None:
    """Reload strategy base definitions and verify the contract surfaces remain exported."""
    reloaded_module = _reload_module(strategy_base_module)

    assert reloaded_module.UserManagerProtocol.__name__ == "UserManagerProtocol"
    assert reloaded_module.Strategy.__abstractmethods__ == {"destroy_token", "read_token", "write_token"}
    assert "with_session" in reloaded_module.SessionBindable.__dict__
    assert "write_refresh_token" in reloaded_module.RefreshableStrategy.__dict__
    assert "rotate_refresh_token" in reloaded_module.RefreshableStrategy.__dict__
    assert "invalidate_all_tokens" in reloaded_module.TokenInvalidationCapable.__dict__


def test_transport_base_module_reload_preserves_abstract_contracts() -> None:
    """Reload transport base definitions and verify the abstract API remains stable."""
    reloaded_module = _reload_module(transport_base_module)

    assert reloaded_module.LogoutTokenReadable.__name__ == "LogoutTokenReadable"
    assert reloaded_module.Transport.__abstractmethods__ == {"read_token", "set_login_token", "set_logout"}


def test_db_base_module_reload_preserves_store_contracts() -> None:
    """Reload persistence contracts and verify the expected methods remain exposed."""
    reloaded_module = _reload_module(db_base_module)

    assert reloaded_module.BaseUserStore.__abstractmethods__ == {
        "create",
        "delete",
        "get",
        "get_by_email",
        "get_by_field",
        "list_users",
        "update",
    }
    assert "get_by_oauth_account" in reloaded_module.BaseOAuthAccountStore.__dict__
    assert "upsert_oauth_account" in reloaded_module.BaseOAuthAccountStore.__dict__


def test_manager_protocols_module_reload_preserves_internal_protocols() -> None:
    """Reload internal manager protocols and verify their required attributes remain defined."""
    reloaded_module = _reload_module(manager_protocols_module)

    assert reloaded_module.ManagedUserProtocol.__annotations__ == {"email": "str", "hashed_password": "str"}
    assert reloaded_module.AccountStateUserProtocol.__name__ == "AccountStateUserProtocol"
    assert reloaded_module.UserDatabaseManagerProtocol.__annotations__ == {"user_db": "Any"}
    assert reloaded_module.PasswordManagedUserManagerProtocol.__annotations__ == {"password_helper": "Any"}
    assert "_normalize_email" in reloaded_module.PasswordManagedUserManagerProtocol.__dict__
    assert "_validate_password" in reloaded_module.PasswordManagedUserManagerProtocol.__dict__


def test_models_module_reload_executes_under_coverage(monkeypatch: pytest.MonkeyPatch) -> None:
    """Reload ORM definition modules in isolation and verify model metadata remains intact."""
    reloaded_module = _load_reloaded_alias(
        alias_name="_coverage_alias_models",
        source_path=REPO_ROOT / "litestar_auth" / "models.py",
        monkeypatch=monkeypatch,
    )

    assert reloaded_module.User.__name__ == "User"
    assert reloaded_module.OAuthAccount.__name__ == "OAuthAccount"
    assert reloaded_module.User.__tablename__ == "user"
    assert reloaded_module.OAuthAccount.__tablename__ == "oauth_account"
    assert set(reloaded_module.User.__table__.c.keys()).issuperset(
        {"email", "hashed_password", "id", "is_active", "is_superuser", "is_verified", "totp_secret"},
    )
    assert set(reloaded_module.OAuthAccount.__table__.c.keys()).issuperset(
        {"access_token", "account_email", "account_id", "expires_at", "id", "oauth_name", "refresh_token", "user_id"},
    )
    assert sorted(reloaded_module.User.__annotations__) == [
        "access_tokens",
        "email",
        "hashed_password",
        "is_active",
        "is_superuser",
        "is_verified",
        "oauth_accounts",
        "refresh_tokens",
        "totp_secret",
    ]
    assert sorted(reloaded_module.OAuthAccount.__annotations__) == [
        "access_token",
        "account_email",
        "account_id",
        "expires_at",
        "oauth_name",
        "refresh_token",
        "user",
        "user_id",
    ]
    assert {
        constraint.name
        for constraint in reloaded_module.OAuthAccount.__table__.constraints
        if constraint.name is not None
    } == {"uq_oauth_account_provider_identity"}
    assert reloaded_module.OAuthAccount.__table__.c.user_id.foreign_keys


def test_db_models_module_reload_executes_under_coverage(monkeypatch: pytest.MonkeyPatch) -> None:
    """Reload token ORM definitions in isolation and verify their mapped columns remain intact."""
    reloaded_module = _load_reloaded_alias(
        alias_name="_coverage_alias_db_models",
        source_path=REPO_ROOT / "litestar_auth" / "authentication" / "strategy" / "db_models.py",
        monkeypatch=monkeypatch,
    )

    assert reloaded_module.AccessToken.__name__ == "AccessToken"
    assert reloaded_module.RefreshToken.__name__ == "RefreshToken"
    assert reloaded_module.AccessToken.__tablename__ == "access_token"
    assert reloaded_module.RefreshToken.__tablename__ == "refresh_token"
    assert set(reloaded_module.AccessToken.__table__.c.keys()).issuperset({"created_at", "token", "user_id"})
    assert set(reloaded_module.RefreshToken.__table__.c.keys()).issuperset({"created_at", "token", "user_id"})
    assert sorted(reloaded_module.AccessToken.__annotations__) == ["created_at", "token", "user", "user_id"]
    assert sorted(reloaded_module.RefreshToken.__annotations__) == ["created_at", "token", "user", "user_id"]
