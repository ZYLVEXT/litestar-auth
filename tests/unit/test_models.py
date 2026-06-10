"""Tests for SQLAlchemy user, role, OAuth, access-token, and refresh-token models."""

from __future__ import annotations

import base64
import sqlite3
import subprocess
import sys
from contextlib import contextmanager
from datetime import UTC, datetime, timedelta
from typing import TYPE_CHECKING, Any, Self, cast, get_type_hints
from uuid import UUID, uuid4

import pytest
from advanced_alchemy.base import UUIDPrimaryKey, create_registry
from sqlalchemy import String, create_engine, event, inspect, select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import DeclarativeBase, Mapped, Session, mapped_column, relationship
from sqlalchemy.pool import StaticPool

import litestar_auth._auth_model_mixins as auth_model_mixins_module
import litestar_auth.models as litestar_auth_models
from litestar_auth._roles import normalize_role_name, normalize_roles
from litestar_auth.authentication.strategy import (
    DatabaseTokenModels as DatabaseTokenModelsFromStrategy,
)
from litestar_auth.authentication.strategy.db_models import (
    AccessToken,
    DatabaseTokenModels,
    RefreshToken,
    RefreshTokenConsumedDigest,
)
from litestar_auth.exceptions import ConfigurationError
from litestar_auth.models._oauth_encrypted_types import (
    oauth_access_token_type,
    oauth_refresh_token_type,
)
from litestar_auth.models.mixins import OrganizationInvitationMixin, OrganizationMembershipMixin, OrganizationMixin
from litestar_auth.oauth_encryption import OAuthTokenEncryption, bind_oauth_token_encryption

AccessTokenMixin = litestar_auth_models.AccessTokenMixin
ApiKey = litestar_auth_models.ApiKey
ApiKeyMixin = litestar_auth_models.ApiKeyMixin
OAuthAccount = litestar_auth_models.OAuthAccount
OAuthAccountMixin = litestar_auth_models.OAuthAccountMixin
Organization = litestar_auth_models.Organization
OrganizationInvitation = litestar_auth_models.OrganizationInvitation
OrganizationMembership = litestar_auth_models.OrganizationMembership
RefreshTokenMixin = litestar_auth_models.RefreshTokenMixin
Role = litestar_auth_models.Role
RoleMixin = litestar_auth_models.RoleMixin
User = litestar_auth_models.User
UserAuthRelationshipMixin = litestar_auth_models.UserAuthRelationshipMixin
UserModelMixin = litestar_auth_models.UserModelMixin
UserRole = litestar_auth_models.UserRole
UserRoleAssociationMixin = litestar_auth_models.UserRoleAssociationMixin
UserRoleRelationshipMixin = litestar_auth_models.UserRoleRelationshipMixin
import_token_orm_models_from_models = litestar_auth_models.import_token_orm_models

if TYPE_CHECKING:
    from collections.abc import Iterator

    from sqlalchemy.engine import Engine

pytestmark = pytest.mark.unit

OAUTH_TOKEN_ENCRYPTION_KEY = base64.urlsafe_b64encode(b"0" * 32).decode()
OAUTH_TOKEN_COLUMN_LENGTH = 4096


@pytest.mark.imports
def test_oauth_submodule_import_does_not_load_reference_user_module() -> None:
    """Importing only ``litestar_auth.models.oauth`` must not execute ``models.user`` (no library ``User`` mapper)."""
    code = (
        "import sys\n"
        "from litestar_auth.models.oauth import OAuthAccount\n"
        'assert "litestar_auth.models.user" not in sys.modules\n'
        'assert OAuthAccount.__tablename__ == "oauth_account"\n'
    )
    result = subprocess.run(
        [sys.executable, "-c", code],
        check=False,
        capture_output=True,
        text=True,
        timeout=60,
    )
    assert result.returncode == 0, (result.stdout, result.stderr)


def test_oauth_token_sqlalchemy_string_length_matches_fernet_headroom() -> None:
    """OAuth columns must store Fernet ciphertext for long provider tokens (see module comment)."""
    assert isinstance(oauth_access_token_type, String)
    assert isinstance(oauth_refresh_token_type, String)
    assert oauth_access_token_type.length == OAUTH_TOKEN_COLUMN_LENGTH
    assert oauth_refresh_token_type.length == OAUTH_TOKEN_COLUMN_LENGTH


def test_models_package_getattr_unknown_name_raises() -> None:
    """``__getattr__`` rejects names outside the lazy public exports (full error branch)."""
    with pytest.raises(AttributeError, match=r"module 'litestar_auth\.models' has no attribute"):
        _ = litestar_auth_models.NonexistentExport


def test_models_package_dir_lists_lazy_exports() -> None:
    """``__dir__`` advertises the public model exports for tab-completion / introspection."""
    assert litestar_auth_models.__dir__() == [  # noqa: PLC2801
        "AccessTokenMixin",
        "ApiKey",
        "ApiKeyMixin",
        "OAuthAccount",
        "OAuthAccountMixin",
        "Organization",
        "OrganizationInvitation",
        "OrganizationInvitationMixin",
        "OrganizationMembership",
        "OrganizationMembershipMixin",
        "OrganizationMixin",
        "RefreshTokenMixin",
        "Role",
        "RoleMixin",
        "User",
        "UserAuthRelationshipMixin",
        "UserModelMixin",
        "UserRole",
        "UserRoleAssociationMixin",
        "UserRoleRelationshipMixin",
        "import_token_orm_models",
    ]


@pytest.mark.imports
def test_models_package_mixins_do_not_load_reference_model_modules() -> None:
    """Importing mixins from ``litestar_auth.models`` keeps the concrete ORM modules deferred."""
    code = (
        "import sys\n"
        "from litestar_auth.models import (\n"
        "    AccessTokenMixin,\n"
        "    ApiKeyMixin,\n"
        "    OAuthAccountMixin,\n"
        "    RefreshTokenMixin,\n"
        "    RoleMixin,\n"
        "    UserAuthRelationshipMixin,\n"
        "    UserModelMixin,\n"
        "    UserRoleAssociationMixin,\n"
        "    UserRoleRelationshipMixin,\n"
        ")\n"
        "from litestar_auth.models.mixins import OrganizationInvitationMixin, OrganizationMembershipMixin, OrganizationMixin\n"
        "assert AccessTokenMixin.__name__ == 'AccessTokenMixin'\n"
        "assert ApiKeyMixin.__name__ == 'ApiKeyMixin'\n"
        "assert OAuthAccountMixin.__name__ == 'OAuthAccountMixin'\n"
        "assert OrganizationInvitationMixin.__name__ == 'OrganizationInvitationMixin'\n"
        "assert OrganizationMembershipMixin.__name__ == 'OrganizationMembershipMixin'\n"
        "assert OrganizationMixin.__name__ == 'OrganizationMixin'\n"
        "assert RefreshTokenMixin.__name__ == 'RefreshTokenMixin'\n"
        "assert RoleMixin.__name__ == 'RoleMixin'\n"
        "assert UserAuthRelationshipMixin.__name__ == 'UserAuthRelationshipMixin'\n"
        "assert UserModelMixin.__name__ == 'UserModelMixin'\n"
        "assert UserRoleAssociationMixin.__name__ == 'UserRoleAssociationMixin'\n"
        "assert UserRoleRelationshipMixin.__name__ == 'UserRoleRelationshipMixin'\n"
        'assert "litestar_auth.models.user" not in sys.modules\n'
        'assert "litestar_auth.models.api_key" not in sys.modules\n'
        'assert "litestar_auth.models.oauth" not in sys.modules\n'
        'assert "litestar_auth.models.organization" not in sys.modules\n'
        'assert "litestar_auth.models.role" not in sys.modules\n'
    )
    result = subprocess.run(
        [sys.executable, "-c", code],
        check=False,
        capture_output=True,
        text=True,
        timeout=60,
    )

    assert result.returncode == 0, (result.stdout, result.stderr)


@contextmanager
def create_test_engine() -> Iterator[Engine]:
    """Yield an in-memory SQLite engine with foreign keys enabled and dispose on exit.

    Yields:
        Configured SQLite engine for model integration tests. The engine is
        disposed when the ``with`` block exits, whether through normal completion
        or an exception, so callers do not need their own ``try/finally``.
    """
    engine = create_engine(
        "sqlite+pysqlite:///:memory:",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )

    @event.listens_for(engine, "connect")
    def _enable_sqlite_foreign_keys(dbapi_connection: sqlite3.Connection, _: object) -> None:
        if not isinstance(dbapi_connection, sqlite3.Connection):
            return

        cursor = dbapi_connection.cursor()
        try:
            cursor.execute("PRAGMA foreign_keys=ON")
        finally:
            cursor.close()

    try:
        yield engine
    finally:
        engine.dispose()


def test_user_model_creates_schema_with_expected_columns() -> None:
    """The bundled model family creates the expected relational role schema."""
    with create_test_engine() as engine:
        User.metadata.create_all(engine)

        inspector = inspect(engine)
        columns = {column["name"]: column for column in inspector.get_columns("user")}
        role_columns = {column["name"]: column for column in inspector.get_columns("role")}
        user_role_columns = {column["name"]: column for column in inspector.get_columns("user_role")}
        email_indexes = inspector.get_indexes("user")
        user_role_foreign_keys = inspector.get_foreign_keys("user_role")

        assert {"role", "user", "user_role"} <= set(inspector.get_table_names())
        assert set(columns) <= {
            "id",
            "email",
            "hashed_password",
            "is_active",
            "is_verified",
            "recovery_codes",
            "sa_orm_sentinel",
            "totp_secret",
        }
        assert "roles" not in columns
        assert role_columns["name"]["nullable"] is False
        assert set(user_role_columns) == {"role_name", "user_id"}
        assert columns["totp_secret"]["nullable"] is True
        assert {foreign_key["referred_table"] for foreign_key in user_role_foreign_keys} == {"role", "user"}
        assert any(index["name"] == "ix_user_email" and index["unique"] == 1 for index in email_indexes)


def test_user_model_persists_defaults_and_generated_uuid() -> None:
    """Persisted users receive default flags and a UUID primary key."""
    with create_test_engine() as engine:
        User.metadata.create_all(engine)

        with Session(engine) as session:
            user = User(email="user@example.com", hashed_password="hashed-password")
            session.add(user)
            session.commit()
            session.refresh(user)

        assert isinstance(user.id, UUID)
        assert user.is_active is True
        assert user.is_verified is False
        assert user.roles == []
        assert user.totp_secret is None
        assert user.recovery_codes is None


def test_user_model_rejects_unexpected_constructor_keyword() -> None:
    """The bundled user model rejects undeclared ORM constructor keywords."""
    with pytest.raises(TypeError, match="unexpected_flag"):
        User(email="user@example.com", hashed_password="hashed-password", unexpected_flag=False)


def test_role_normalization_helpers_preserve_flat_membership_contract() -> None:
    """The shared role helpers normalize iterables and scalar names consistently."""
    assert normalize_roles([" Billing ", "admin", "ADMIN"]) == ["admin", "billing"]
    assert normalize_roles((" Support ", "admin", "ADMIN")) == ["admin", "support"]
    assert normalize_roles(None) == []
    assert normalize_role_name(" Support ") == "support"


def test_user_model_normalizes_roles_and_persists_relational_membership() -> None:
    """Bundled users persist deterministic roles through role and user-role tables."""
    with create_test_engine() as engine:
        User.metadata.create_all(engine)

        with Session(engine) as session:
            user = User(
                email="roles@example.com",
                hashed_password="hashed-password",
                roles=[" Billing ", "admin", "ADMIN"],
            )
            session.add(user)
            session.commit()
            session.refresh(user)

            assert user.roles == ["admin", "billing"]
            assert isinstance(user.roles, list)
            assert session.execute(select(Role.name).order_by(Role.name)).scalars().all() == ["admin", "billing"]
            assert session.execute(select(UserRole.role_name).order_by(UserRole.role_name)).scalars().all() == [
                "admin",
                "billing",
            ]


def test_user_model_role_reassignment_replaces_assignment_rows() -> None:
    """Assigning a new role iterable replaces the stored association rows."""
    with create_test_engine() as engine:
        User.metadata.create_all(engine)

        with Session(engine) as session:
            user = User(email="reassign@example.com", hashed_password="hashed-password", roles=["admin", "billing"])
            session.add(user)
            session.commit()

            user.roles = [" Support ", "admin", "ADMIN"]
            session.commit()
            session.refresh(user)

            assert user.roles == ["admin", "support"]
            assert session.execute(select(UserRole.role_name).order_by(UserRole.role_name)).scalars().all() == [
                "admin",
                "support",
            ]


def test_role_catalog_rows_are_global_and_unique_across_users() -> None:
    """Repeated role names reuse one role row while keeping per-user assignment rows."""
    with create_test_engine() as engine:
        User.metadata.create_all(engine)

        with Session(engine) as session:
            session.add_all(
                [
                    User(email="first@example.com", hashed_password="first-hash", roles=["admin"]),
                    User(email="second@example.com", hashed_password="second-hash", roles=["ADMIN", "support"]),
                ],
            )
            session.commit()

            assert session.execute(select(Role.name).order_by(Role.name)).scalars().all() == ["admin", "support"]
            assert session.execute(
                select(UserRole.role_name).order_by(UserRole.role_name, UserRole.user_id),
            ).scalars().all() == [
                "admin",
                "admin",
                "support",
            ]


def test_pending_role_catalog_rows_are_reused_during_user_role_flush() -> None:
    """Pre-created pending role rows satisfy assignment flushes without duplicates."""
    with create_test_engine() as engine:
        User.metadata.create_all(engine)

        with Session(engine) as session:
            session.add(Role(name=" Admin "))
            session.add(User(email="pending-role@example.com", hashed_password="hashed-password", roles=["admin"]))
            session.commit()

            assert session.execute(select(Role.name)).scalars().all() == ["admin"]
            assert session.execute(select(UserRole.role_name)).scalars().all() == ["admin"]


def test_insert_missing_role_row_ignores_duplicate_role_race_when_role_now_exists() -> None:
    """Concurrent duplicate role creation is tolerated when the winner row now exists."""

    class _Savepoint:
        def __enter__(self) -> Self:
            return self

        def __exit__(self, exc_type: object, exc: object, traceback: object) -> bool:
            return False

    class _Connection:
        def begin_nested(self) -> _Savepoint:
            return _Savepoint()

        def execute(self, statement: object) -> None:
            statement_text = "INSERT INTO role (name) VALUES (?)"
            raise IntegrityError(statement_text, {"name": "admin"}, sqlite3.IntegrityError())

    class _Session:
        def connection(self) -> _Connection:
            return _Connection()

        def scalar(self, statement: object) -> str:
            return "admin"

    auth_model_mixins_module._insert_missing_role_row(
        cast("Any", _Session()),
        role_model=Role,
        role_name_column=Role.name,
        role_name="admin",
    )


def test_insert_missing_role_row_reraises_non_duplicate_integrity_errors() -> None:
    """Unexpected role-row insert failures are not silently swallowed."""

    class _Savepoint:
        def __enter__(self) -> Self:
            return self

        def __exit__(self, exc_type: object, exc: object, traceback: object) -> bool:
            return False

    class _Connection:
        def begin_nested(self) -> _Savepoint:
            return _Savepoint()

        def execute(self, statement: object) -> None:
            statement_text = "INSERT INTO role (name) VALUES (?)"
            raise IntegrityError(statement_text, {"name": "admin"}, sqlite3.IntegrityError())

    class _Session:
        def connection(self) -> _Connection:
            return _Connection()

        def scalar(self, statement: object) -> None:
            pass

    with pytest.raises(IntegrityError):
        auth_model_mixins_module._insert_missing_role_row(
            cast("Any", _Session()),
            role_model=Role,
            role_name_column=Role.name,
            role_name="admin",
        )


def test_user_model_enforces_unique_email_constraint() -> None:
    """Duplicate user emails are rejected by the database."""
    with create_test_engine() as engine:
        User.metadata.create_all(engine)

        with Session(engine) as session:
            session.add(User(email="duplicate@example.com", hashed_password="first-hash"))
            session.commit()
            session.add(User(email="duplicate@example.com", hashed_password="second-hash"))

            with pytest.raises(IntegrityError):
                session.commit()


def test_oauth_account_model_creates_schema_and_relationship() -> None:
    """OAuth accounts create their table and link back to users."""
    with create_test_engine() as engine:
        User.metadata.create_all(engine)

        inspector = inspect(engine)
        oauth_columns = {column["name"]: column for column in inspector.get_columns("oauth_account")}
        foreign_keys = inspector.get_foreign_keys("oauth_account")

        assert "oauth_account" in inspector.get_table_names()
        assert set(oauth_columns).issuperset(
            {
                "id",
                "user_id",
                "oauth_name",
                "account_id",
                "account_email",
                "access_token",
                "expires_at",
                "refresh_token",
            },
        )
        assert foreign_keys[0]["referred_table"] == "user"

        with Session(engine) as session:
            bind_oauth_token_encryption(session, OAuthTokenEncryption(key=OAUTH_TOKEN_ENCRYPTION_KEY))
            user = User(email="oauth@example.com", hashed_password="hashed-password")
            oauth_account = OAuthAccount(
                user=user,
                oauth_name="github",
                account_id="github-user-1",
                account_email="oauth@example.com",
                access_token="access-token",
                expires_at=1_700_000_000,
                refresh_token="refresh-token",
            )
            session.add_all([user, oauth_account])
            session.commit()
            session.refresh(user)
            session.refresh(oauth_account)

            assert oauth_account.user_id == user.id
            assert oauth_account.user is user
            assert user.oauth_accounts == [oauth_account]


def test_oauth_account_model_enforces_foreign_key_constraint() -> None:
    """Orphan OAuth accounts are rejected by the database."""
    with create_test_engine() as engine:
        User.metadata.create_all(engine)

        with Session(engine) as session:
            bind_oauth_token_encryption(session, OAuthTokenEncryption(key=OAUTH_TOKEN_ENCRYPTION_KEY))
            session.add(
                OAuthAccount(
                    user_id=UUID("00000000-0000-0000-0000-000000000001"),
                    oauth_name="google",
                    account_id="google-user-1",
                    account_email="ghost@example.com",
                    access_token="access-token",
                ),
            )

            with pytest.raises(IntegrityError):
                session.commit()


def test_access_token_model_creates_schema_and_relationship() -> None:
    """Access tokens create their table and link back to users."""
    with create_test_engine() as engine:
        User.metadata.create_all(engine)

        inspector = inspect(engine)
        access_token_columns = {column["name"]: column for column in inspector.get_columns("access_token")}
        foreign_keys = inspector.get_foreign_keys("access_token")
        primary_key = inspector.get_pk_constraint("access_token")

        assert "access_token" in inspector.get_table_names()
        assert primary_key["constrained_columns"] == ["token"]
        assert set(access_token_columns).issuperset({"token", "user_id", "created_at"})
        assert access_token_columns["created_at"]["default"] is not None
        assert foreign_keys[0]["referred_table"] == "user"

        with Session(engine) as session:
            user = User(email="token@example.com", hashed_password="hashed-password")
            access_token = AccessToken(token="access-token-1", user=user)
            session.add_all([user, access_token])
            session.commit()
            session.refresh(user)
            session.refresh(access_token)

            assert access_token.user_id == user.id
            assert access_token.user is user
            assert user.access_tokens == [access_token]
            assert access_token.created_at is not None


def test_models_package_import_token_orm_models_returns_token_model_classes() -> None:
    """The canonical models-layer helper returns the mapped token model classes."""
    assert import_token_orm_models_from_models() == (AccessToken, RefreshToken, RefreshTokenConsumedDigest)


def test_models_package_import_token_orm_models_matches_database_token_models_defaults() -> None:
    """The canonical models helper stays aligned with the explicit DB-token model contract."""
    access_token_model, refresh_token_model, consumed_digest_model = import_token_orm_models_from_models()
    token_models = DatabaseTokenModels()

    assert import_token_orm_models_from_models.__module__ == "litestar_auth.models.tokens"
    assert (token_models.access_token_model, token_models.refresh_token_model) == (
        access_token_model,
        refresh_token_model,
    )
    assert token_models.consumed_refresh_token_digest_model is consumed_digest_model is RefreshTokenConsumedDigest


def test_models_package_import_token_orm_models_annotations_are_runtime_resolvable() -> None:
    """The canonical models helper keeps runtime-resolvable token-model annotations."""
    hints = get_type_hints(import_token_orm_models_from_models)

    assert hints["return"] == tuple[type[AccessToken], type[RefreshToken], type[RefreshTokenConsumedDigest]]


def test_database_token_models_default_to_bundled_token_model_classes() -> None:
    """The explicit DB-token model contract defaults to the bundled ORM classes."""
    token_models = DatabaseTokenModels()

    assert DatabaseTokenModelsFromStrategy is DatabaseTokenModels
    assert token_models.access_token_model is AccessToken
    assert token_models.refresh_token_model is RefreshToken
    assert token_models.consumed_refresh_token_digest_model is RefreshTokenConsumedDigest


def test_database_token_models_accept_custom_consumed_digest_model_contract() -> None:
    """The explicit DB-token model contract accepts a custom consumed-digest lookup model."""

    class CustomConsumedRefreshTokenDigest:
        token_digest = object()
        session_id = object()
        consumed_at = object()

    token_models = DatabaseTokenModels(
        consumed_refresh_token_digest_model=CustomConsumedRefreshTokenDigest,
    )

    assert token_models.consumed_refresh_token_digest_model is CustomConsumedRefreshTokenDigest


@pytest.mark.parametrize(
    ("field_name", "access_token_model", "refresh_token_model", "consumed_digest_model", "missing_attribute"),
    [
        pytest.param(
            "access_token_model",
            type("BadAccessToken", (), {}),
            RefreshToken,
            RefreshTokenConsumedDigest,
            "token",
            id="invalid-access-token-model",
        ),
        pytest.param(
            "refresh_token_model",
            AccessToken,
            type("BadRefreshToken", (), {}),
            RefreshTokenConsumedDigest,
            "token",
            id="invalid-refresh-token-model",
        ),
        pytest.param(
            "refresh_token_model",
            AccessToken,
            type(
                "IncompleteRefreshToken",
                (),
                {
                    "token": object(),
                    "created_at": object(),
                    "user_id": object(),
                    "user": object(),
                },
            ),
            RefreshTokenConsumedDigest,
            "session_id",
            id="refresh-token-model-missing-session-contract",
        ),
        pytest.param(
            "consumed_refresh_token_digest_model",
            AccessToken,
            RefreshToken,
            type("BadConsumedRefreshTokenDigest", (), {}),
            "token_digest",
            id="invalid-consumed-digest-model",
        ),
    ],
)
def test_database_token_models_reject_invalid_model_contracts(
    field_name: str,
    access_token_model: type[object],
    refresh_token_model: type[object],
    consumed_digest_model: type[object],
    missing_attribute: str,
) -> None:
    """Invalid token-model classes fail fast with a stable configuration error."""
    with pytest.raises(ConfigurationError, match=rf"{field_name}.*{missing_attribute}"):
        DatabaseTokenModels(
            access_token_model=access_token_model,
            refresh_token_model=refresh_token_model,
            consumed_refresh_token_digest_model=consumed_digest_model,
        )


@pytest.mark.imports
def test_user_relationship_mixin_supports_custom_user_contract_without_reference_user_module() -> None:
    """Custom user models can compose the shared user mixins without importing the bundled ``User``."""
    code = (
        "import sys\n"
        "from advanced_alchemy.base import UUIDBase\n"
        "from sqlalchemy import inspect\n"
        "from litestar_auth.authentication.strategy.db_models import AccessToken, RefreshToken\n"
        "from litestar_auth.models.oauth import OAuthAccount\n"
        "from litestar_auth.models import UserAuthRelationshipMixin, UserModelMixin\n"
        "assert 'litestar_auth.models.user' not in sys.modules\n"
        "class User(UserModelMixin, UserAuthRelationshipMixin, UUIDBase):\n"
        "    __tablename__ = 'user'\n"
        "user_relationships = inspect(User).relationships\n"
        "assert sorted(user_relationships.keys()) == ['access_tokens', 'oauth_accounts', 'refresh_tokens']\n"
        "assert user_relationships['access_tokens'].mapper.class_ is AccessToken\n"
        "assert user_relationships['refresh_tokens'].mapper.class_ is RefreshToken\n"
        "assert user_relationships['oauth_accounts'].mapper.class_ is OAuthAccount\n"
        "assert inspect(AccessToken).relationships['user'].mapper.class_ is User\n"
        "assert inspect(RefreshToken).relationships['user'].mapper.class_ is User\n"
        "assert inspect(OAuthAccount).relationships['user'].mapper.class_ is User\n"
    )
    result = subprocess.run(
        [sys.executable, "-c", code],
        check=False,
        capture_output=True,
        text=True,
        timeout=60,
    )

    assert result.returncode == 0, (result.stdout, result.stderr)


@pytest.mark.imports
def test_database_token_models_support_custom_mixin_token_contract_without_reference_models() -> None:
    """The public token-model contract can point at mixin-composed custom token models."""
    code = (
        "import sys\n"
        "from sqlalchemy.orm import DeclarativeBase\n"
        "from advanced_alchemy.base import UUIDPrimaryKey, create_registry\n"
        "from litestar_auth.authentication.strategy import DatabaseTokenModels\n"
        "from litestar_auth.models import AccessTokenMixin, RefreshTokenMixin, UserAuthRelationshipMixin, UserModelMixin\n"
        "assert 'litestar_auth.models.user' not in sys.modules\n"
        "class AppBase(DeclarativeBase):\n"
        "    registry = create_registry()\n"
        "    metadata = registry.metadata\n"
        "    __abstract__ = True\n"
        "class AppUUIDBase(UUIDPrimaryKey, AppBase):\n"
        "    __abstract__ = True\n"
        "class MyUser(UserModelMixin, UserAuthRelationshipMixin, AppUUIDBase):\n"
        "    __tablename__ = 'my_user'\n"
        "    auth_access_token_model = 'MyAccessToken'\n"
        "    auth_refresh_token_model = 'MyRefreshToken'\n"
        "    auth_oauth_account_model = None\n"
        "class MyAccessToken(AccessTokenMixin, AppBase):\n"
        "    __tablename__ = 'my_access_token'\n"
        "    auth_user_model = 'MyUser'\n"
        "    auth_user_table = 'my_user'\n"
        "class MyRefreshToken(RefreshTokenMixin, AppBase):\n"
        "    __tablename__ = 'my_refresh_token'\n"
        "    auth_user_model = 'MyUser'\n"
        "    auth_user_table = 'my_user'\n"
        "token_models = DatabaseTokenModels(access_token_model=MyAccessToken, refresh_token_model=MyRefreshToken)\n"
        "assert token_models.access_token_model is MyAccessToken\n"
        "assert token_models.refresh_token_model is MyRefreshToken\n"
        "assert 'litestar_auth.models.user' not in sys.modules\n"
    )
    result = subprocess.run(
        [sys.executable, "-c", code],
        check=False,
        capture_output=True,
        text=True,
        timeout=60,
    )

    assert result.returncode == 0, (result.stdout, result.stderr)


@pytest.mark.imports
def test_optional_model_mixins_support_custom_auth_family_contract_without_reference_models() -> None:
    """Custom user, token, and OAuth models can compose the supported mixins without bundled model imports."""
    code = (
        "import sys\n"
        "from sqlalchemy import inspect\n"
        "from sqlalchemy.orm import DeclarativeBase\n"
        "from advanced_alchemy.base import UUIDPrimaryKey, create_registry\n"
        "from litestar_auth.models import (\n"
        "    AccessTokenMixin,\n"
        "    OAuthAccountMixin,\n"
        "    RefreshTokenMixin,\n"
        "    UserAuthRelationshipMixin,\n"
        "    UserModelMixin,\n"
        ")\n"
        "assert 'litestar_auth.models.user' not in sys.modules\n"
        "assert 'litestar_auth.models.oauth' not in sys.modules\n"
        "class AppBase(DeclarativeBase):\n"
        "    registry = create_registry()\n"
        "    metadata = registry.metadata\n"
        "    __abstract__ = True\n"
        "class AppUUIDBase(UUIDPrimaryKey, AppBase):\n"
        "    __abstract__ = True\n"
        "class MyUser(UserModelMixin, UserAuthRelationshipMixin, AppUUIDBase):\n"
        "    __tablename__ = 'my_user'\n"
        "    auth_access_token_model = 'MyAccessToken'\n"
        "    auth_refresh_token_model = 'MyRefreshToken'\n"
        "    auth_oauth_account_model = 'MyOAuthAccount'\n"
        "class MyAccessToken(AccessTokenMixin, AppBase):\n"
        "    __tablename__ = 'my_access_token'\n"
        "    auth_user_model = 'MyUser'\n"
        "    auth_user_table = 'my_user'\n"
        "class MyRefreshToken(RefreshTokenMixin, AppBase):\n"
        "    __tablename__ = 'my_refresh_token'\n"
        "    auth_user_model = 'MyUser'\n"
        "    auth_user_table = 'my_user'\n"
        "class MyOAuthAccount(OAuthAccountMixin, AppUUIDBase):\n"
        "    __tablename__ = 'my_oauth_account'\n"
        "    auth_user_model = 'MyUser'\n"
        "    auth_user_table = 'my_user'\n"
        "user_relationships = inspect(MyUser).relationships\n"
        "assert user_relationships['access_tokens'].mapper.class_ is MyAccessToken\n"
        "assert user_relationships['refresh_tokens'].mapper.class_ is MyRefreshToken\n"
        "assert user_relationships['oauth_accounts'].mapper.class_ is MyOAuthAccount\n"
        "assert inspect(MyAccessToken).relationships['user'].mapper.class_ is MyUser\n"
        "assert inspect(MyRefreshToken).relationships['user'].mapper.class_ is MyUser\n"
        "assert inspect(MyOAuthAccount).relationships['user'].mapper.class_ is MyUser\n"
        "assert next(iter(MyAccessToken.__table__.c.user_id.foreign_keys)).target_fullname == 'my_user.id'\n"
        "assert next(iter(MyRefreshToken.__table__.c.user_id.foreign_keys)).target_fullname == 'my_user.id'\n"
        "assert next(iter(MyOAuthAccount.__table__.c.user_id.foreign_keys)).target_fullname == 'my_user.id'\n"
    )
    result = subprocess.run(
        [sys.executable, "-c", code],
        check=False,
        capture_output=True,
        text=True,
        timeout=60,
    )

    assert result.returncode == 0, (result.stdout, result.stderr)


def test_custom_user_model_can_map_hashed_password_to_custom_column_via_supported_hook() -> None:
    """Custom users can map ``hashed_password`` to ``password_hash`` via the mixin hook."""

    class CustomPasswordColumnBase(DeclarativeBase):
        """App-owned registry for a custom password-column contract."""

        registry = create_registry()
        metadata = registry.metadata
        __abstract__ = True

    class CustomPasswordColumnUUIDBase(UUIDPrimaryKey, CustomPasswordColumnBase):
        """UUID primary-key base for the custom password-column contract."""

        __abstract__ = True

    class CustomPasswordColumnUser(UserModelMixin, UserAuthRelationshipMixin, CustomPasswordColumnUUIDBase):
        """Custom user model that keeps the ``hashed_password`` attribute on a custom SQL column."""

        __tablename__ = "custom_password_column_user"

        auth_access_token_model = "CustomPasswordColumnAccessToken"
        auth_refresh_token_model = "CustomPasswordColumnRefreshToken"
        auth_oauth_account_model = "CustomPasswordColumnOAuthAccount"
        auth_hashed_password_column_name = "password_hash"

    class CustomPasswordColumnAccessToken(AccessTokenMixin, CustomPasswordColumnBase):
        """Custom access-token model paired with the custom password-column user."""

        __tablename__ = "custom_password_column_access_token"

        auth_user_model = "CustomPasswordColumnUser"
        auth_user_table = "custom_password_column_user"

    class CustomPasswordColumnRefreshToken(RefreshTokenMixin, CustomPasswordColumnBase):
        """Custom refresh-token model paired with the custom password-column user."""

        __tablename__ = "custom_password_column_refresh_token"

        auth_user_model = "CustomPasswordColumnUser"
        auth_user_table = "custom_password_column_user"

    class CustomPasswordColumnOAuthAccount(OAuthAccountMixin, CustomPasswordColumnUUIDBase):
        """Custom OAuth-account model paired with the custom password-column user."""

        __tablename__ = "custom_password_column_oauth_account"

        auth_user_model = "CustomPasswordColumnUser"
        auth_user_table = "custom_password_column_user"

    with create_test_engine() as engine:
        CustomPasswordColumnUser.metadata.create_all(engine)

        inspector = inspect(engine)
        user_columns = {column["name"] for column in inspector.get_columns("custom_password_column_user")}

        assert "password_hash" in user_columns
        assert "hashed_password" not in user_columns
        assert CustomPasswordColumnUser.__mapper__.attrs["hashed_password"].columns[0].name == "password_hash"
        user_relationships = inspect(CustomPasswordColumnUser).relationships
        assert user_relationships["access_tokens"].mapper.class_ is CustomPasswordColumnAccessToken
        assert user_relationships["refresh_tokens"].mapper.class_ is CustomPasswordColumnRefreshToken
        assert user_relationships["oauth_accounts"].mapper.class_ is CustomPasswordColumnOAuthAccount

        with Session(engine) as session:
            user = CustomPasswordColumnUser(email="custom-password-column@example.com", hashed_password="custom-hash")
            session.add(user)
            session.commit()

            stored_hash = session.execute(select(CustomPasswordColumnUser.__table__.c.password_hash)).scalar_one()

        assert stored_hash == "custom-hash"


def test_custom_role_mixins_round_trip_normalized_membership() -> None:
    """App-owned role-capable users can compose the supported relational role mixins."""

    class CustomRolesBase(DeclarativeBase):
        """App-owned registry for custom-role coverage."""

        registry = create_registry()
        metadata = registry.metadata
        __abstract__ = True

    class CustomRolesUUIDBase(UUIDPrimaryKey, CustomRolesBase):
        """UUID primary-key base for custom-role coverage."""

        __abstract__ = True

    class CustomRolesUser(UserModelMixin, UserRoleRelationshipMixin, CustomRolesUUIDBase):
        """Custom user model using the shared relational role contract."""

        __tablename__ = "custom_roles_user"

        auth_user_role_model = "CustomUserRole"
        auth_user_role_relationship_lazy = ""

    class CustomRole(RoleMixin, CustomRolesBase):
        """Custom global role catalog row."""

        __tablename__ = "custom_role"

        auth_user_role_model = "CustomUserRole"
        auth_user_role_relationship_lazy = "selectin"

    class CustomUserRole(UserRoleAssociationMixin, CustomRolesBase):
        """Custom user-role association row."""

        __tablename__ = "custom_user_role"

        auth_user_model = "CustomRolesUser"
        auth_user_table = "custom_roles_user"
        auth_role_model = "CustomRole"
        auth_role_table = "custom_role"

    with create_test_engine() as engine:
        CustomRolesUser.metadata.create_all(engine)

        inspector = inspect(engine)
        user_columns = {column["name"] for column in inspector.get_columns("custom_roles_user")}
        role_columns = {column["name"] for column in inspector.get_columns("custom_role")}
        user_role_columns = {column["name"] for column in inspector.get_columns("custom_user_role")}

        assert "roles" not in user_columns
        assert role_columns == {"name"}
        assert user_role_columns == {"role_name", "user_id"}
        assert inspect(CustomRolesUser).relationships["role_assignments"].lazy == "select"
        assert inspect(CustomRole).relationships["user_assignments"].lazy == "selectin"
        assert CustomUserRole.__tablename__ == "custom_user_role"

        with Session(engine) as session:
            user = CustomRolesUser(
                email="custom-roles@example.com",
                hashed_password="custom-hash",
                roles=[" Support ", "admin", "ADMIN"],
            )
            session.add(user)
            session.commit()
            session.refresh(user)

            assert user.roles == ["admin", "support"]
            assert isinstance(user.roles, list)
            assert session.execute(select(CustomRole.name).order_by(CustomRole.name)).scalars().all() == [
                "admin",
                "support",
            ]


def test_organization_mixins_map_columns_relationships_and_normalize_roles() -> None:
    """Organization mixins compose a side-effect-free tenant membership schema."""

    class OrganizationBase(DeclarativeBase):
        """App-owned registry for organization mixin coverage."""

        registry = create_registry()
        metadata = registry.metadata
        __abstract__ = True

    class OrganizationUUIDBase(UUIDPrimaryKey, OrganizationBase):
        """UUID primary-key base for organization user coverage."""

        __abstract__ = True

    class OrganizationUser(UserModelMixin, OrganizationUUIDBase):
        """Custom user model with an organization-membership inverse relationship."""

        __tablename__ = "organization_user"

        organization_memberships: Mapped[list[Any]] = relationship(
            "OrganizationMembership",
            back_populates="user",
            cascade="all, delete-orphan",
            passive_deletes=True,
        )

    class Organization(OrganizationMixin, OrganizationBase):
        """Custom organization catalog row."""

        __tablename__ = "organization"
        auth_organization_invitation_model = "OrganizationInvitation"
        auth_organization_invitation_relationship_lazy = "selectin"

    class OrganizationMembership(OrganizationMembershipMixin, OrganizationBase):
        """Custom join row linking one user to one organization."""

        __tablename__ = "organization_membership"

        auth_user_model = "OrganizationUser"
        auth_user_table = "organization_user"

    class OrganizationInvitation(OrganizationInvitationMixin, OrganizationBase):
        """Custom invitation row linked to one organization."""

        __tablename__ = "organization_invitation"
        auth_organization_relationship_foreign_keys = False

    with create_test_engine() as engine:
        OrganizationUser.metadata.create_all(engine)

        inspector = inspect(engine)
        organization_columns = {column["name"]: column for column in inspector.get_columns("organization")}
        membership_columns = {column["name"]: column for column in inspector.get_columns("organization_membership")}
        invitation_columns = {column["name"]: column for column in inspector.get_columns("organization_invitation")}
        membership_foreign_keys = inspector.get_foreign_keys("organization_membership")
        invitation_foreign_keys = inspector.get_foreign_keys("organization_invitation")
        membership_primary_key = inspector.get_pk_constraint("organization_membership")
        organization_indexes = inspector.get_indexes("organization")

        assert set(organization_columns) == {"created_at", "id", "name", "slug", "updated_at"}
        assert organization_columns["slug"]["nullable"] is False
        assert organization_columns["name"]["nullable"] is False
        assert set(membership_columns) == {"organization_id", "roles", "user_id"}
        assert set(invitation_columns) == {
            "created_at",
            "expires_at",
            "id",
            "invited_email",
            "organization_id",
            "roles",
            "status",
            "token_hash",
        }
        assert set(membership_primary_key["constrained_columns"]) == {"organization_id", "user_id"}
        assert inspector.get_unique_constraints("organization_membership") == []
        assert {foreign_key["referred_table"] for foreign_key in membership_foreign_keys} == {
            "organization",
            "organization_user",
        }
        assert {foreign_key["referred_table"] for foreign_key in invitation_foreign_keys} == {"organization"}
        assert any(index["name"] == "ix_organization_slug" and index["unique"] == 1 for index in organization_indexes)
        assert inspect(Organization).relationships["memberships"].mapper.class_ is OrganizationMembership
        assert inspect(Organization).relationships["invitations"].mapper.class_ is OrganizationInvitation
        assert inspect(Organization).relationships["invitations"].lazy == "selectin"
        assert inspect(OrganizationMembership).relationships["user"].mapper.class_ is OrganizationUser
        assert inspect(OrganizationMembership).relationships["organization"].mapper.class_ is Organization
        assert inspect(OrganizationInvitation).relationships["organization"].mapper.class_ is Organization
        assert inspect(OrganizationInvitation).relationships["organization"]._user_defined_foreign_keys == set()

        with Session(engine) as session:
            user = OrganizationUser(email="member@example.com", hashed_password="custom-hash")
            organization = Organization(slug=" Billing ", name="Billing")
            membership = OrganizationMembership(
                user=user,
                organization=organization,
                roles=[" Admin ", "ADMIN", "member"],
            )
            invitation = OrganizationInvitation(
                organization=organization,
                invited_email=" Invitee@Example.COM ",
                roles=[" Member ", "member", "admin"],
                token_hash=b"custom-invitation-token-hash".ljust(64, b"0"),
                expires_at=datetime.now(tz=UTC) + timedelta(hours=1),
            )
            session.add_all([membership, invitation])
            session.commit()
            session.refresh(organization)
            session.refresh(membership)
            session.refresh(invitation)

            assert organization.slug == "billing"
            assert membership.roles == ["admin", "member"]
            assert invitation.invited_email == "invitee@example.com"
            assert invitation.roles == ["admin", "member"]
            assert user.organization_memberships == [membership]
            assert organization.memberships == [membership]


def test_organization_invitation_mixin_rejects_invalid_email() -> None:
    """Invitation email validation uses the account email normalization rules."""
    with pytest.raises(ValueError, match="Invalid email address"):
        OrganizationInvitation(
            organization_id=uuid4(),
            invited_email="not-an-email",
            roles=["member"],
            token_hash=b"invalid-invitation-token-hash".ljust(64, b"0"),
            expires_at=datetime.now(tz=UTC) + timedelta(hours=1),
        )


def test_organization_mixins_support_custom_user_and_organization_targets() -> None:
    """Organization membership hooks can target app-owned user and organization tables."""

    class CustomOrganizationBase(DeclarativeBase):
        """App-owned registry for custom organization-table coverage."""

        registry = create_registry()
        metadata = registry.metadata
        __abstract__ = True

    class CustomOrganizationUUIDBase(UUIDPrimaryKey, CustomOrganizationBase):
        """UUID primary-key base for custom organization user coverage."""

        __abstract__ = True

    class TenantUser(UserModelMixin, CustomOrganizationUUIDBase):
        """Custom user table with a custom membership collection name."""

        __tablename__ = "tenant_user"

        tenant_links: Mapped[list[Any]] = relationship(
            "TenantLink",
            back_populates="user",
            cascade="all, delete-orphan",
            passive_deletes=True,
        )

    class Tenant(OrganizationMixin, CustomOrganizationBase):
        """Custom organization table with a custom membership collection name."""

        __tablename__ = "tenant"

        auth_organization_membership_model = "TenantLink"
        auth_organization_membership_relationship_lazy = "selectin"

    class TenantLink(OrganizationMembershipMixin, CustomOrganizationBase):
        """Custom organization membership row using every table/model override."""

        __tablename__ = "tenant_link"

        auth_user_model = "TenantUser"
        auth_user_table = "tenant_user"
        auth_user_back_populates = "tenant_links"
        auth_organization_model = "Tenant"
        auth_organization_table = "tenant"
        auth_organization_relationship_foreign_keys = False

    with create_test_engine() as engine:
        TenantUser.metadata.create_all(engine)

        inspector = inspect(engine)
        membership_foreign_keys = inspector.get_foreign_keys("tenant_link")
        membership_primary_key = inspector.get_pk_constraint("tenant_link")
        membership_unique_constraints = inspector.get_unique_constraints("tenant_link")
        relationships = inspect(TenantLink).relationships

        assert {foreign_key["referred_table"] for foreign_key in membership_foreign_keys} == {"tenant", "tenant_user"}
        assert set(membership_primary_key["constrained_columns"]) == {"organization_id", "user_id"}
        assert membership_unique_constraints == []
        assert inspect(Tenant).relationships["memberships"].lazy == "selectin"
        assert relationships["user"].mapper.class_ is TenantUser
        assert relationships["organization"].mapper.class_ is Tenant


def test_custom_user_model_can_define_hashed_password_mapping_directly() -> None:
    """Custom users can define the ``hashed_password`` mapping directly when they own the attribute contract."""

    class DirectPasswordColumnBase(DeclarativeBase):
        """App-owned registry for direct password-column mapping coverage."""

        registry = create_registry()
        metadata = registry.metadata
        __abstract__ = True

    class DirectPasswordColumnUUIDBase(UUIDPrimaryKey, DirectPasswordColumnBase):
        """UUID primary-key base for direct password-column mapping coverage."""

        __abstract__ = True

    class DirectPasswordColumnUser(UserModelMixin, DirectPasswordColumnUUIDBase):
        """Custom user model that owns the ``hashed_password`` mapped attribute directly."""

        __tablename__ = "direct_password_column_user"

        hashed_password: Mapped[str] = mapped_column("password_hash", String(length=255))

    with create_test_engine() as engine:
        DirectPasswordColumnUser.metadata.create_all(engine)

        inspector = inspect(engine)
        user_columns = {column["name"] for column in inspector.get_columns("direct_password_column_user")}

        assert "password_hash" in user_columns
        assert "hashed_password" not in user_columns
        assert DirectPasswordColumnUser.__mapper__.attrs["hashed_password"].columns[0].name == "password_hash"

        with Session(engine) as session:
            user = DirectPasswordColumnUser(email="direct@example.com", hashed_password="direct-hash")
            session.add(user)
            session.commit()

            stored_hash = session.execute(select(DirectPasswordColumnUser.__table__.c.password_hash)).scalar_one()

        assert stored_hash == "direct-hash"


@pytest.mark.imports
def test_optional_model_mixins_support_partial_oauth_customization() -> None:
    """Custom users can compose only the OAuth branch of the auth model family."""
    code = (
        "from sqlalchemy import inspect\n"
        "from sqlalchemy.orm import DeclarativeBase\n"
        "from advanced_alchemy.base import UUIDPrimaryKey, create_registry\n"
        "from litestar_auth.models import OAuthAccountMixin, UserAuthRelationshipMixin, UserModelMixin\n"
        "class AppBase(DeclarativeBase):\n"
        "    registry = create_registry()\n"
        "    metadata = registry.metadata\n"
        "    __abstract__ = True\n"
        "class AppUUIDBase(UUIDPrimaryKey, AppBase):\n"
        "    __abstract__ = True\n"
        "class MyUser(UserModelMixin, UserAuthRelationshipMixin, AppUUIDBase):\n"
        "    __tablename__ = 'my_user'\n"
        "    auth_access_token_model = None\n"
        "    auth_refresh_token_model = None\n"
        "    auth_oauth_account_model = 'MyOAuthAccount'\n"
        "class MyOAuthAccount(OAuthAccountMixin, AppUUIDBase):\n"
        "    __tablename__ = 'my_oauth_account'\n"
        "    auth_user_model = 'MyUser'\n"
        "    auth_user_table = 'my_user'\n"
        "user_relationships = inspect(MyUser).relationships\n"
        "assert sorted(user_relationships.keys()) == ['oauth_accounts']\n"
        "assert MyUser.access_tokens is None\n"
        "assert MyUser.refresh_tokens is None\n"
        "assert user_relationships['oauth_accounts'].mapper.class_ is MyOAuthAccount\n"
        "assert inspect(MyOAuthAccount).relationships['user'].mapper.class_ is MyUser\n"
        "assert next(iter(MyOAuthAccount.__table__.c.user_id.foreign_keys)).target_fullname == 'my_user.id'\n"
    )
    result = subprocess.run(
        [sys.executable, "-c", code],
        check=False,
        capture_output=True,
        text=True,
        timeout=60,
    )

    assert result.returncode == 0, (result.stdout, result.stderr)


@pytest.mark.imports
def test_models_package_import_token_orm_models_keeps_user_relationship_unresolved_until_user_model_exists() -> None:
    """Token registration via ``litestar_auth.models`` stays lazy until a ``User`` mapper exists."""
    code = (
        "import sys\n"
        "from sqlalchemy.exc import InvalidRequestError\n"
        "from litestar_auth.models import import_token_orm_models\n"
        "AccessToken, RefreshToken, RefreshTokenConsumedDigest = import_token_orm_models()\n"
        'assert "litestar_auth.models.user" not in sys.modules\n'
        'assert "litestar_auth.models.oauth" not in sys.modules\n'
        "assert (AccessToken.__name__, RefreshToken.__name__, RefreshTokenConsumedDigest.__name__) == (\n"
        "    'AccessToken',\n"
        "    'RefreshToken',\n"
        "    'RefreshTokenConsumedDigest',\n"
        ")\n"
        "try:\n"
        "    _ = AccessToken.user.property\n"
        "except InvalidRequestError as exc:\n"
        "    assert \"expression 'User' failed to locate a name\" in str(exc)\n"
        "else:\n"
        "    raise AssertionError('AccessToken.user unexpectedly resolved without a User mapper')\n"
    )
    result = subprocess.run(
        [sys.executable, "-c", code],
        check=False,
        capture_output=True,
        text=True,
        timeout=60,
    )

    assert result.returncode == 0, (result.stdout, result.stderr)


def test_reference_user_model_inverse_relationship_contracts_are_stable() -> None:  # noqa: PLR0915
    """The bundled ``User`` model keeps token and OAuth inverse relationships wired to the current classes."""
    user_relationships = inspect(User).relationships

    assert issubclass(User, UserModelMixin)
    assert issubclass(User, UserRoleRelationshipMixin)
    assert issubclass(User, UserAuthRelationshipMixin)
    assert issubclass(Role, RoleMixin)
    assert issubclass(UserRole, UserRoleAssociationMixin)
    assert issubclass(OAuthAccount, OAuthAccountMixin)
    assert issubclass(Organization, OrganizationMixin)
    assert issubclass(OrganizationInvitation, OrganizationInvitationMixin)
    assert issubclass(OrganizationMembership, OrganizationMembershipMixin)
    assert issubclass(ApiKey, ApiKeyMixin)
    assert issubclass(AccessToken, AccessTokenMixin)
    assert issubclass(RefreshToken, RefreshTokenMixin)
    assert sorted(user_relationships.keys()) == [
        "access_tokens",
        "api_keys",
        "oauth_accounts",
        "organization_memberships",
        "refresh_tokens",
        "role_assignments",
    ]
    assert user_relationships["access_tokens"].mapper.class_ is AccessToken
    assert user_relationships["access_tokens"].back_populates == "user"
    assert user_relationships["access_tokens"].lazy == "select"
    assert user_relationships["access_tokens"]._user_defined_foreign_keys == set()
    assert [(left.key, right.key) for left, right in user_relationships["access_tokens"].synchronize_pairs] == [
        ("id", "user_id"),
    ]
    assert user_relationships["access_tokens"].uselist is True
    assert user_relationships["api_keys"].mapper.class_ is ApiKey
    assert user_relationships["api_keys"].back_populates == "user"
    assert user_relationships["api_keys"].lazy == "select"
    assert user_relationships["api_keys"]._user_defined_foreign_keys == set()
    assert [(left.key, right.key) for left, right in user_relationships["api_keys"].synchronize_pairs] == [
        ("id", "user_id"),
    ]
    assert user_relationships["api_keys"].uselist is True
    assert user_relationships["refresh_tokens"].mapper.class_ is RefreshToken
    assert user_relationships["refresh_tokens"].back_populates == "user"
    assert user_relationships["refresh_tokens"].lazy == "select"
    assert user_relationships["refresh_tokens"]._user_defined_foreign_keys == set()
    assert [(left.key, right.key) for left, right in user_relationships["refresh_tokens"].synchronize_pairs] == [
        ("id", "user_id"),
    ]
    assert user_relationships["refresh_tokens"].uselist is True
    assert user_relationships["oauth_accounts"].mapper.class_ is OAuthAccount
    assert user_relationships["oauth_accounts"].back_populates == "user"
    assert user_relationships["oauth_accounts"].lazy == "select"
    assert user_relationships["oauth_accounts"]._user_defined_foreign_keys == set()
    assert [(left.key, right.key) for left, right in user_relationships["oauth_accounts"].synchronize_pairs] == [
        ("id", "user_id"),
    ]
    assert user_relationships["oauth_accounts"].uselist is True
    assert user_relationships["organization_memberships"].mapper.class_ is OrganizationMembership
    assert user_relationships["organization_memberships"].back_populates == "user"
    assert user_relationships["organization_memberships"].lazy == "select"
    assert user_relationships["organization_memberships"]._user_defined_foreign_keys == set()
    assert [
        (left.key, right.key) for left, right in user_relationships["organization_memberships"].synchronize_pairs
    ] == [
        ("id", "user_id"),
    ]
    assert user_relationships["organization_memberships"].uselist is True
    assert user_relationships["role_assignments"].mapper.class_ is UserRole
    assert user_relationships["role_assignments"].back_populates == "user"
    assert user_relationships["role_assignments"].lazy == "selectin"
    assert user_relationships["role_assignments"]._user_defined_foreign_keys == set()
    assert [(left.key, right.key) for left, right in user_relationships["role_assignments"].synchronize_pairs] == [
        ("id", "user_id"),
    ]
    assert user_relationships["role_assignments"].uselist is True
    assert inspect(AccessToken).relationships["user"].mapper.class_ is User
    assert inspect(AccessToken).relationships["user"].back_populates == "access_tokens"
    assert inspect(ApiKey).relationships["user"].mapper.class_ is User
    assert inspect(ApiKey).relationships["user"].back_populates == "api_keys"
    assert inspect(RefreshToken).relationships["user"].mapper.class_ is User
    assert inspect(RefreshToken).relationships["user"].back_populates == "refresh_tokens"
    assert inspect(OAuthAccount).relationships["user"].mapper.class_ is User
    assert inspect(OAuthAccount).relationships["user"].back_populates == "oauth_accounts"
    assert inspect(OrganizationMembership).relationships["user"].mapper.class_ is User
    assert inspect(OrganizationMembership).relationships["user"].back_populates == "organization_memberships"
    assert inspect(OrganizationMembership).relationships["organization"].mapper.class_ is Organization
    assert inspect(OrganizationMembership).relationships["organization"].back_populates == "memberships"
    assert inspect(OrganizationInvitation).relationships["organization"].mapper.class_ is Organization
    assert inspect(OrganizationInvitation).relationships["organization"].back_populates == "invitations"
    assert inspect(Organization).relationships["invitations"].mapper.class_ is OrganizationInvitation
    assert inspect(Organization).relationships["invitations"].back_populates == "organization"
    assert inspect(Organization).relationships["memberships"].mapper.class_ is OrganizationMembership
    assert inspect(Organization).relationships["memberships"].back_populates == "organization"
    assert inspect(UserRole).relationships["user"].mapper.class_ is User
    assert inspect(UserRole).relationships["user"].back_populates == "role_assignments"
    assert inspect(UserRole).relationships["role"].mapper.class_ is Role
    assert inspect(UserRole).relationships["role"].back_populates == "user_assignments"
    assert inspect(Role).relationships["user_assignments"].mapper.class_ is UserRole
    assert inspect(Role).relationships["user_assignments"].back_populates == "role"


@pytest.mark.imports
def test_user_relationship_mixin_supports_relationship_option_overrides() -> None:
    """Custom user models can override supported relationship options without changing inverse wiring."""
    code = (
        "from sqlalchemy import inspect\n"
        "from sqlalchemy.orm import DeclarativeBase\n"
        "from advanced_alchemy.base import UUIDPrimaryKey, create_registry\n"
        "from litestar_auth.models import (\n"
        "    AccessTokenMixin,\n"
        "    OAuthAccountMixin,\n"
        "    RefreshTokenMixin,\n"
        "    UserAuthRelationshipMixin,\n"
        "    UserModelMixin,\n"
        ")\n"
        "class AppBase(DeclarativeBase):\n"
        "    registry = create_registry()\n"
        "    metadata = registry.metadata\n"
        "    __abstract__ = True\n"
        "class AppUUIDBase(UUIDPrimaryKey, AppBase):\n"
        "    __abstract__ = True\n"
        "class ConfiguredUser(UserModelMixin, UserAuthRelationshipMixin, AppUUIDBase):\n"
        "    __tablename__ = 'configured_user'\n"
        "    auth_access_token_model = 'ConfiguredAccessToken'\n"
        "    auth_refresh_token_model = 'ConfiguredRefreshToken'\n"
        "    auth_oauth_account_model = 'ConfiguredOAuthAccount'\n"
        "    auth_token_relationship_lazy = 'noload'\n"
        "    auth_oauth_account_relationship_lazy = 'selectin'\n"
        "    auth_oauth_account_relationship_foreign_keys = 'ConfiguredOAuthAccount.user_id'\n"
        "class ConfiguredAccessToken(AccessTokenMixin, AppBase):\n"
        "    __tablename__ = 'configured_access_token'\n"
        "    auth_user_model = 'ConfiguredUser'\n"
        "    auth_user_table = 'configured_user'\n"
        "class ConfiguredRefreshToken(RefreshTokenMixin, AppBase):\n"
        "    __tablename__ = 'configured_refresh_token'\n"
        "    auth_user_model = 'ConfiguredUser'\n"
        "    auth_user_table = 'configured_user'\n"
        "class ConfiguredOAuthAccount(OAuthAccountMixin, AppUUIDBase):\n"
        "    __tablename__ = 'configured_oauth_account'\n"
        "    auth_user_model = 'ConfiguredUser'\n"
        "    auth_user_table = 'configured_user'\n"
        "relationships = inspect(ConfiguredUser).relationships\n"
        "assert sorted(relationships.keys()) == ['access_tokens', 'oauth_accounts', 'refresh_tokens']\n"
        "assert relationships['access_tokens'].mapper.class_ is ConfiguredAccessToken\n"
        "assert relationships['access_tokens'].lazy == 'noload'\n"
        "assert relationships['access_tokens']._user_defined_foreign_keys == set()\n"
        "assert [(left.key, right.key) for left, right in relationships['access_tokens'].synchronize_pairs] == [\n"
        "    ('id', 'user_id')\n"
        "]\n"
        "assert relationships['refresh_tokens'].mapper.class_ is ConfiguredRefreshToken\n"
        "assert relationships['refresh_tokens'].lazy == 'noload'\n"
        "assert relationships['refresh_tokens']._user_defined_foreign_keys == set()\n"
        "assert [(left.key, right.key) for left, right in relationships['refresh_tokens'].synchronize_pairs] == [\n"
        "    ('id', 'user_id')\n"
        "]\n"
        "assert relationships['oauth_accounts'].mapper.class_ is ConfiguredOAuthAccount\n"
        "assert relationships['oauth_accounts'].lazy == 'selectin'\n"
        "assert relationships['oauth_accounts']._user_defined_foreign_keys == {ConfiguredOAuthAccount.__table__.c.user_id}\n"
        "assert [(left.key, right.key) for left, right in relationships['oauth_accounts'].synchronize_pairs] == [\n"
        "    ('id', 'user_id')\n"
        "]\n"
        "assert inspect(ConfiguredAccessToken).relationships['user'].mapper.class_ is ConfiguredUser\n"
        "assert inspect(ConfiguredRefreshToken).relationships['user'].mapper.class_ is ConfiguredUser\n"
        "assert inspect(ConfiguredOAuthAccount).relationships['user'].mapper.class_ is ConfiguredUser\n"
    )
    result = subprocess.run(
        [sys.executable, "-c", code],
        check=False,
        capture_output=True,
        text=True,
        timeout=60,
    )

    assert result.returncode == 0, (result.stdout, result.stderr)


def test_access_token_model_enforces_foreign_key_constraint() -> None:
    """Orphan access tokens are rejected by the database."""
    with create_test_engine() as engine:
        User.metadata.create_all(engine)

        with Session(engine) as session:
            session.add(
                AccessToken(
                    token="access-token-orphan",
                    user_id=UUID("00000000-0000-0000-0000-000000000001"),
                ),
            )

            with pytest.raises(IntegrityError):
                session.commit()


def test_refresh_token_model_creates_schema_and_relationship() -> None:
    """Refresh tokens create their table and link back to users."""
    with create_test_engine() as engine:
        User.metadata.create_all(engine)

        inspector = inspect(engine)
        refresh_token_columns = {column["name"]: column for column in inspector.get_columns("refresh_token")}
        foreign_keys = inspector.get_foreign_keys("refresh_token")
        primary_key = inspector.get_pk_constraint("refresh_token")

        assert "refresh_token" in inspector.get_table_names()
        assert primary_key["constrained_columns"] == ["token"]
        assert "consumed_token_digests" not in refresh_token_columns
        assert set(refresh_token_columns).issuperset(
            {
                "token",
                "user_id",
                "created_at",
                "session_id",
                "last_used_at",
                "client_metadata",
            },
        )
        assert refresh_token_columns["created_at"]["default"] is not None
        assert refresh_token_columns["session_id"]["nullable"] is False
        assert refresh_token_columns["last_used_at"]["nullable"] is True
        assert refresh_token_columns["client_metadata"]["nullable"] is True
        assert any(index["name"] == "ix_refresh_token_session_id" for index in inspector.get_indexes("refresh_token"))
        assert foreign_keys[0]["referred_table"] == "user"

        with Session(engine) as session:
            user = User(email="refresh@example.com", hashed_password="hashed-password")
            refresh_token = RefreshToken(token="refresh-token-1", user=user)
            session.add_all([user, refresh_token])
            session.commit()
            session.refresh(user)
            session.refresh(refresh_token)

            assert refresh_token.user_id == user.id
            assert refresh_token.user is user
            assert user.refresh_tokens == [refresh_token]
            assert refresh_token.created_at is not None
            assert refresh_token.session_id != refresh_token.token
            assert isinstance(UUID(refresh_token.session_id), UUID)
            assert refresh_token.last_used_at is None
            assert refresh_token.client_metadata is None


def test_refresh_token_consumed_digest_model_creates_indexed_lookup_table() -> None:
    """Consumed refresh-token digests are indexed separately for replay lookup."""
    with create_test_engine() as engine:
        access_token_model, refresh_token_model, consumed_digest_model = import_token_orm_models_from_models()
        access_token_model.metadata.create_all(engine)

        inspector = inspect(engine)
        consumed_digest_columns = {
            column["name"]: column for column in inspector.get_columns("refresh_token_consumed_digest")
        }
        primary_key = inspector.get_pk_constraint("refresh_token_consumed_digest")

        assert (access_token_model, refresh_token_model, consumed_digest_model) == (
            AccessToken,
            RefreshToken,
            RefreshTokenConsumedDigest,
        )
        assert {"access_token", "refresh_token", "refresh_token_consumed_digest"}.issubset(inspector.get_table_names())
        assert "refresh_token_consumed_digest" in inspector.get_table_names()
        assert primary_key["constrained_columns"] == ["token_digest"]
        assert set(consumed_digest_columns) == {"token_digest", "session_id", "consumed_at"}
        assert consumed_digest_columns["session_id"]["nullable"] is False
        assert consumed_digest_columns["consumed_at"]["nullable"] is False
        assert any(
            index["name"] == "ix_refresh_token_consumed_digest_session_id"
            for index in inspector.get_indexes("refresh_token_consumed_digest")
        )

        with Session(engine) as session:
            marker = consumed_digest_model(token_digest="consumed-digest", session_id="session-id")
            session.add(marker)
            session.commit()
            session.refresh(marker)

            assert marker.consumed_at is not None


def test_refresh_token_model_enforces_foreign_key_constraint() -> None:
    """Orphan refresh tokens are rejected by the database."""
    with create_test_engine() as engine:
        User.metadata.create_all(engine)

        with Session(engine) as session:
            session.add(
                RefreshToken(
                    token="refresh-token-orphan",
                    user_id=UUID("00000000-0000-0000-0000-000000000001"),
                ),
            )

            with pytest.raises(IntegrityError):
                session.commit()


def test_api_key_model_creates_schema_and_relationship() -> None:
    """API keys create their table, indexes, and user relationship."""
    with create_test_engine() as engine:
        User.metadata.create_all(engine)

        inspector = inspect(engine)
        api_key_columns = {column["name"]: column for column in inspector.get_columns("api_key")}
        indexes = inspector.get_indexes("api_key")
        foreign_keys = inspector.get_foreign_keys("api_key")

        assert "api_key" in inspector.get_table_names()
        assert set(api_key_columns).issuperset(
            {
                "id",
                "key_id",
                "user_id",
                "hashed_secret",
                "encrypted_secret",
                "name",
                "scopes",
                "prefix_env",
                "signing_required",
                "expires_at",
                "last_used_at",
                "created_at",
                "revoked_at",
                "created_via",
                "client_metadata",
            },
        )
        assert api_key_columns["key_id"]["nullable"] is False
        assert api_key_columns["user_id"]["nullable"] is False
        assert api_key_columns["hashed_secret"]["nullable"] is False
        assert api_key_columns["encrypted_secret"]["nullable"] is True
        assert api_key_columns["client_metadata"]["nullable"] is True
        assert any(index["name"] == "ix_api_key_key_id" and index["unique"] == 1 for index in indexes)
        assert any(index["name"] == "ix_api_key_user_id" and index["unique"] == 0 for index in indexes)
        assert foreign_keys[0]["referred_table"] == "user"

        with Session(engine) as session:
            user = User(email="api-key@example.com", hashed_password="hashed-password")
            api_key = ApiKey(
                key_id="akid_1",
                user=user,
                hashed_secret=b"hashed-secret",
                encrypted_secret=None,
                name="Automation",
                scopes=["read", "write"],
                prefix_env="prod",
                signing_required=False,
                created_via="test",
                client_metadata={"user_agent": "Unit Test/1.0"},
            )
            session.add_all([user, api_key])
            session.commit()
            session.refresh(user)
            session.refresh(api_key)

            assert api_key.user_id == user.id
            assert api_key.user is user
            assert user.api_keys == [api_key]
            assert api_key.hashed_secret == b"hashed-secret"
            assert api_key.encrypted_secret is None
            assert api_key.created_at is not None
            assert api_key.revoked_at is None


def test_api_key_model_rejects_unbounded_client_metadata() -> None:
    """API-key metadata follows the same 64/255 key-value bounds as public session metadata."""
    assert (
        ApiKey(
            key_id="akid_no_metadata",
            user_id=UUID("00000000-0000-0000-0000-000000000001"),
            hashed_secret=b"hashed-secret",
            name="No metadata",
            scopes=[],
            prefix_env="prod",
            signing_required=False,
            created_via="test",
            client_metadata=None,
        ).client_metadata
        is None
    )

    with pytest.raises(ValueError, match="client_metadata keys"):
        ApiKey(
            key_id="akid_invalid_key",
            user_id=UUID("00000000-0000-0000-0000-000000000001"),
            hashed_secret=b"hashed-secret",
            name="Invalid",
            scopes=[],
            prefix_env="prod",
            signing_required=False,
            created_via="test",
            client_metadata={"x" * 65: "value"},
        )

    with pytest.raises(ValueError, match="client_metadata keys"):
        ApiKey(
            key_id="akid_invalid_key_pattern",
            user_id=UUID("00000000-0000-0000-0000-000000000001"),
            hashed_secret=b"hashed-secret",
            name="Invalid",
            scopes=[],
            prefix_env="prod",
            signing_required=False,
            created_via="test",
            client_metadata={"User-Agent": "value"},
        )

    with pytest.raises(ValueError, match="client_metadata keys"):
        ApiKey(
            key_id="akid_invalid_value",
            user_id=UUID("00000000-0000-0000-0000-000000000001"),
            hashed_secret=b"hashed-secret",
            name="Invalid",
            scopes=[],
            prefix_env="prod",
            signing_required=False,
            created_via="test",
            client_metadata={"user_agent": "x" * 256},
        )


@pytest.mark.imports
def test_models_package_import_token_orm_models_resolves_to_reference_user_relationships_after_user_import() -> None:
    """After the bundled ``User`` model loads, the helper-returned token classes bind correctly."""
    code = (
        "from sqlalchemy import inspect\n"
        "from litestar_auth.models import import_token_orm_models\n"
        "AccessToken, RefreshToken, RefreshTokenConsumedDigest = import_token_orm_models()\n"
        "from litestar_auth.models import ApiKey\n"
        "from litestar_auth.models import User\n"
        "from litestar_auth.models.oauth import OAuthAccount\n"
        "user_relationships = inspect(User).relationships\n"
        "assert user_relationships['api_keys'].mapper.class_ is ApiKey\n"
        "assert user_relationships['api_keys'].back_populates == 'user'\n"
        "assert user_relationships['access_tokens'].mapper.class_ is AccessToken\n"
        "assert user_relationships['access_tokens'].back_populates == 'user'\n"
        "assert user_relationships['refresh_tokens'].mapper.class_ is RefreshToken\n"
        "assert user_relationships['refresh_tokens'].back_populates == 'user'\n"
        "assert RefreshTokenConsumedDigest.__tablename__ == 'refresh_token_consumed_digest'\n"
        "assert user_relationships['oauth_accounts'].mapper.class_ is OAuthAccount\n"
        "assert user_relationships['oauth_accounts'].back_populates == 'user'\n"
    )
    result = subprocess.run(
        [sys.executable, "-c", code],
        check=False,
        capture_output=True,
        text=True,
        timeout=60,
    )

    assert result.returncode == 0, (result.stdout, result.stderr)


@pytest.mark.imports
def test_db_models_module_still_exposes_low_level_token_registration_helper() -> None:
    """Importing the db-models module directly still exposes its low-level helper."""
    code = (
        "from importlib import import_module\n"
        "db_models = import_module('litestar_auth.authentication.strategy.db_models')\n"
        "from litestar_auth.models import import_token_orm_models as import_token_orm_models_from_models\n"
        "expected = (db_models.AccessToken, db_models.RefreshToken, db_models.RefreshTokenConsumedDigest)\n"
        "assert db_models.import_token_orm_models() == expected\n"
        "assert import_token_orm_models_from_models() == expected\n"
    )
    result = subprocess.run(
        [sys.executable, "-c", code],
        check=False,
        capture_output=True,
        text=True,
        timeout=60,
    )

    assert result.returncode == 0, (result.stdout, result.stderr)


@pytest.mark.imports
def test_plugin_runtime_bootstrap_is_idempotent_with_models_helper() -> None:
    """Plugin runtime bootstrap and the explicit models helper share one bundled token registration path."""
    code = (
        "import sys\n"
        "from typing import Any, cast\n"
        "from litestar.config.app import AppConfig\n"
        "from litestar_auth.manager import UserManagerSecurity\n"
        "from litestar_auth.plugin import LitestarAuth, LitestarAuthConfig\n"
        "from litestar_auth._plugin.config import DatabaseTokenAuthConfig\n"
        "class UserModel:\n"
        "    email = 'user@example.com'\n"
        "    roles = []\n"
        "class UserManager:\n"
        "    def __init__(self, user_db: object, **kwargs: object) -> None:\n"
        "        self.user_db = user_db\n"
        "        self.kwargs = kwargs\n"
        "class DummySessionMaker:\n"
        "    def __call__(self) -> object:\n"
        "        return object()\n"
        "config = LitestarAuthConfig(\n"
        "    database_token_auth=DatabaseTokenAuthConfig(token_hash_secret='x' * 40),\n"
        "    user_model=UserModel,\n"
        "    user_manager_class=cast(Any, UserManager),\n"
        "    session_maker=cast(Any, DummySessionMaker()),\n"
        "    user_manager_security=UserManagerSecurity(\n"
        "        verification_token_secret='y' * 32,\n"
        "        reset_password_token_secret='z' * 32,\n"
        "    ),\n"
        ")\n"
        "plugin = LitestarAuth(config)\n"
        "plugin.on_app_init(AppConfig())\n"
        "from litestar_auth.models import import_token_orm_models\n"
        "first = import_token_orm_models()\n"
        "second = import_token_orm_models()\n"
        "assert first == second\n"
        "assert [model.__name__ for model in first] == [\n"
        "    'AccessToken',\n"
        "    'RefreshToken',\n"
        "    'RefreshTokenConsumedDigest',\n"
        "]\n"
        "assert 'litestar_auth.models.user' not in sys.modules\n"
        "assert 'litestar_auth.models.oauth' not in sys.modules\n"
    )
    result = subprocess.run(
        [sys.executable, "-c", code],
        check=False,
        capture_output=True,
        text=True,
        timeout=60,
    )

    assert result.returncode == 0, (result.stdout, result.stderr)
