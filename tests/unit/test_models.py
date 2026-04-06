"""Tests for SQLAlchemy user, OAuth, access-token, and refresh-token models."""

from __future__ import annotations

import sqlite3
import subprocess
import sys
from typing import TYPE_CHECKING, get_type_hints
from uuid import UUID

import pytest
from sqlalchemy import create_engine, event, inspect
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session
from sqlalchemy.pool import StaticPool

import litestar_auth.models as litestar_auth_models
from litestar_auth.authentication.strategy import (
    DatabaseTokenModels as DatabaseTokenModelsFromStrategy,
)
from litestar_auth.authentication.strategy import import_token_orm_models as import_token_orm_models_from_strategy
from litestar_auth.authentication.strategy.db_models import AccessToken, DatabaseTokenModels, RefreshToken
from litestar_auth.exceptions import ConfigurationError
from litestar_auth.models import (
    AccessTokenMixin,
    OAuthAccount,
    OAuthAccountMixin,
    RefreshTokenMixin,
    User,
    UserAuthRelationshipMixin,
    UserModelMixin,
)
from litestar_auth.models import (
    import_token_orm_models as import_token_orm_models_from_models,
)

if TYPE_CHECKING:
    from sqlalchemy.engine import Engine

pytestmark = pytest.mark.unit


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


def test_models_package_getattr_unknown_name_raises() -> None:
    """``__getattr__`` rejects names outside the lazy public exports (full error branch)."""
    with pytest.raises(AttributeError, match=r"module 'litestar_auth\.models' has no attribute"):
        _ = litestar_auth_models.NonexistentExport


def test_models_package_dir_lists_lazy_exports() -> None:
    """``__dir__`` advertises the public model exports for tab-completion / introspection."""
    assert litestar_auth_models.__dir__() == [  # noqa: PLC2801
        "AccessTokenMixin",
        "OAuthAccount",
        "OAuthAccountMixin",
        "RefreshTokenMixin",
        "User",
        "UserAuthRelationshipMixin",
        "UserModelMixin",
        "import_token_orm_models",
    ]


@pytest.mark.imports
def test_models_package_mixins_do_not_load_reference_model_modules() -> None:
    """Importing mixins from ``litestar_auth.models`` keeps the concrete ORM modules deferred."""
    code = (
        "import sys\n"
        "from litestar_auth.models import (\n"
        "    AccessTokenMixin,\n"
        "    OAuthAccountMixin,\n"
        "    RefreshTokenMixin,\n"
        "    UserAuthRelationshipMixin,\n"
        "    UserModelMixin,\n"
        ")\n"
        "assert AccessTokenMixin.__name__ == 'AccessTokenMixin'\n"
        "assert OAuthAccountMixin.__name__ == 'OAuthAccountMixin'\n"
        "assert RefreshTokenMixin.__name__ == 'RefreshTokenMixin'\n"
        "assert UserAuthRelationshipMixin.__name__ == 'UserAuthRelationshipMixin'\n"
        "assert UserModelMixin.__name__ == 'UserModelMixin'\n"
        'assert "litestar_auth.models.user" not in sys.modules\n'
        'assert "litestar_auth.models.oauth" not in sys.modules\n'
    )
    result = subprocess.run(
        [sys.executable, "-c", code],
        check=False,
        capture_output=True,
        text=True,
        timeout=60,
    )

    assert result.returncode == 0, (result.stdout, result.stderr)


def create_test_engine() -> Engine:
    """Create an in-memory SQLite engine with foreign keys enabled.

    Returns:
        Configured SQLite engine for model integration tests.
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

    return engine


def test_user_model_creates_schema_with_expected_columns() -> None:
    """The user model can create its table and exposes the required schema."""
    engine = create_test_engine()
    try:
        User.metadata.create_all(engine)

        inspector = inspect(engine)
        columns = {column["name"]: column for column in inspector.get_columns("user")}
        email_indexes = inspector.get_indexes("user")

        assert "user" in inspector.get_table_names()
        assert set(columns).issuperset(
            {
                "id",
                "email",
                "hashed_password",
                "is_active",
                "is_verified",
                "is_superuser",
                "totp_secret",
            },
        )
        assert columns["totp_secret"]["nullable"] is True
        assert any(index["name"] == "ix_user_email" and index["unique"] == 1 for index in email_indexes)
    finally:
        engine.dispose()


def test_user_model_persists_defaults_and_generated_uuid() -> None:
    """Persisted users receive default flags and a UUID primary key."""
    engine = create_test_engine()
    try:
        User.metadata.create_all(engine)

        with Session(engine) as session:
            user = User(email="user@example.com", hashed_password="hashed-password")
            session.add(user)
            session.commit()
            session.refresh(user)

        assert isinstance(user.id, UUID)
        assert user.is_active is True
        assert user.is_verified is False
        assert user.is_superuser is False
        assert user.totp_secret is None
    finally:
        engine.dispose()


def test_user_model_enforces_unique_email_constraint() -> None:
    """Duplicate user emails are rejected by the database."""
    engine = create_test_engine()
    try:
        User.metadata.create_all(engine)

        with Session(engine) as session:
            session.add(User(email="duplicate@example.com", hashed_password="first-hash"))
            session.commit()
            session.add(User(email="duplicate@example.com", hashed_password="second-hash"))

            with pytest.raises(IntegrityError):
                session.commit()
    finally:
        engine.dispose()


def test_oauth_account_model_creates_schema_and_relationship() -> None:
    """OAuth accounts create their table and link back to users."""
    engine = create_test_engine()
    try:
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
    finally:
        engine.dispose()


def test_oauth_account_model_enforces_foreign_key_constraint() -> None:
    """Orphan OAuth accounts are rejected by the database."""
    engine = create_test_engine()
    try:
        User.metadata.create_all(engine)

        with Session(engine) as session:
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
    finally:
        engine.dispose()


def test_access_token_model_creates_schema_and_relationship() -> None:
    """Access tokens create their table and link back to users."""
    engine = create_test_engine()
    try:
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
    finally:
        engine.dispose()


def test_models_package_import_token_orm_models_returns_token_model_classes() -> None:
    """The canonical models-layer helper returns the mapped token model classes."""
    assert import_token_orm_models_from_models() == (AccessToken, RefreshToken)
    assert import_token_orm_models_from_strategy() == import_token_orm_models_from_models()


def test_models_package_import_token_orm_models_matches_database_token_models_defaults() -> None:
    """The canonical models helper stays aligned with the explicit DB-token model contract."""
    access_token_model, refresh_token_model = import_token_orm_models_from_models()
    token_models = DatabaseTokenModels()

    assert import_token_orm_models_from_models.__module__ == "litestar_auth.models.tokens"
    assert import_token_orm_models_from_strategy.__module__ == "litestar_auth.authentication.strategy.db_models"
    assert (token_models.access_token_model, token_models.refresh_token_model) == (
        access_token_model,
        refresh_token_model,
    )


def test_models_package_import_token_orm_models_annotations_are_runtime_resolvable() -> None:
    """The canonical models helper keeps runtime-resolvable token-model annotations."""
    hints = get_type_hints(import_token_orm_models_from_models)

    assert hints["return"] == tuple[type[AccessToken], type[RefreshToken]]


def test_database_token_models_default_to_bundled_token_model_classes() -> None:
    """The explicit DB-token model contract defaults to the bundled ORM classes."""
    token_models = DatabaseTokenModels()

    assert DatabaseTokenModelsFromStrategy is DatabaseTokenModels
    assert token_models.access_token_model is AccessToken
    assert token_models.refresh_token_model is RefreshToken


@pytest.mark.parametrize(
    ("field_name", "access_token_model", "refresh_token_model", "missing_attribute"),
    [
        pytest.param(
            "access_token_model",
            type("BadAccessToken", (), {}),
            RefreshToken,
            "token",
            id="invalid-access-token-model",
        ),
        pytest.param(
            "refresh_token_model",
            AccessToken,
            type("BadRefreshToken", (), {}),
            "token",
            id="invalid-refresh-token-model",
        ),
    ],
)
def test_database_token_models_reject_invalid_model_contracts(
    field_name: str,
    access_token_model: type[object],
    refresh_token_model: type[object],
    missing_attribute: str,
) -> None:
    """Invalid token-model classes fail fast with a stable configuration error."""
    with pytest.raises(ConfigurationError, match=rf"{field_name}.*{missing_attribute}"):
        DatabaseTokenModels(
            access_token_model=access_token_model,
            refresh_token_model=refresh_token_model,
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
        "from litestar_auth.authentication.strategy import import_token_orm_models as strategy_import_token_orm_models\n"
        "from litestar_auth.models import import_token_orm_models\n"
        "AccessToken, RefreshToken = import_token_orm_models()\n"
        "assert strategy_import_token_orm_models() == (AccessToken, RefreshToken)\n"
        'assert "litestar_auth.models.user" not in sys.modules\n'
        'assert "litestar_auth.models.oauth" not in sys.modules\n'
        "assert (AccessToken.__name__, RefreshToken.__name__) == ('AccessToken', 'RefreshToken')\n"
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


def test_reference_user_model_inverse_relationship_contracts_are_stable() -> None:
    """The bundled ``User`` model keeps token and OAuth inverse relationships wired to the current classes."""
    user_relationships = inspect(User).relationships

    assert issubclass(User, UserModelMixin)
    assert issubclass(User, UserAuthRelationshipMixin)
    assert issubclass(OAuthAccount, OAuthAccountMixin)
    assert issubclass(AccessToken, AccessTokenMixin)
    assert issubclass(RefreshToken, RefreshTokenMixin)
    assert sorted(user_relationships.keys()) == ["access_tokens", "oauth_accounts", "refresh_tokens"]
    assert user_relationships["access_tokens"].mapper.class_ is AccessToken
    assert user_relationships["access_tokens"].back_populates == "user"
    assert user_relationships["access_tokens"].lazy == "select"
    assert user_relationships["access_tokens"]._user_defined_foreign_keys == set()
    assert [(left.key, right.key) for left, right in user_relationships["access_tokens"].synchronize_pairs] == [
        ("id", "user_id"),
    ]
    assert user_relationships["access_tokens"].uselist is True
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
    assert inspect(AccessToken).relationships["user"].mapper.class_ is User
    assert inspect(AccessToken).relationships["user"].back_populates == "access_tokens"
    assert inspect(RefreshToken).relationships["user"].mapper.class_ is User
    assert inspect(RefreshToken).relationships["user"].back_populates == "refresh_tokens"
    assert inspect(OAuthAccount).relationships["user"].mapper.class_ is User
    assert inspect(OAuthAccount).relationships["user"].back_populates == "oauth_accounts"


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
    engine = create_test_engine()
    try:
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
    finally:
        engine.dispose()


def test_refresh_token_model_creates_schema_and_relationship() -> None:
    """Refresh tokens create their table and link back to users."""
    engine = create_test_engine()
    try:
        User.metadata.create_all(engine)

        inspector = inspect(engine)
        refresh_token_columns = {column["name"]: column for column in inspector.get_columns("refresh_token")}
        foreign_keys = inspector.get_foreign_keys("refresh_token")
        primary_key = inspector.get_pk_constraint("refresh_token")

        assert "refresh_token" in inspector.get_table_names()
        assert primary_key["constrained_columns"] == ["token"]
        assert set(refresh_token_columns).issuperset({"token", "user_id", "created_at"})
        assert refresh_token_columns["created_at"]["default"] is not None
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
    finally:
        engine.dispose()


def test_refresh_token_model_enforces_foreign_key_constraint() -> None:
    """Orphan refresh tokens are rejected by the database."""
    engine = create_test_engine()
    try:
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
    finally:
        engine.dispose()


@pytest.mark.imports
def test_models_package_import_token_orm_models_resolves_to_reference_user_relationships_after_user_import() -> None:
    """After the bundled ``User`` model loads, the helper-returned token classes bind correctly."""
    code = (
        "from sqlalchemy import inspect\n"
        "from litestar_auth.authentication.strategy import import_token_orm_models as strategy_import_token_orm_models\n"
        "from litestar_auth.models import import_token_orm_models\n"
        "AccessToken, RefreshToken = import_token_orm_models()\n"
        "assert strategy_import_token_orm_models() == (AccessToken, RefreshToken)\n"
        "from litestar_auth.models import User\n"
        "from litestar_auth.models.oauth import OAuthAccount\n"
        "user_relationships = inspect(User).relationships\n"
        "assert user_relationships['access_tokens'].mapper.class_ is AccessToken\n"
        "assert user_relationships['access_tokens'].back_populates == 'user'\n"
        "assert user_relationships['refresh_tokens'].mapper.class_ is RefreshToken\n"
        "assert user_relationships['refresh_tokens'].back_populates == 'user'\n"
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
def test_db_models_side_effect_import_still_exposes_token_registration_helper() -> None:
    """Importing the db-models module for mapper registration still works in isolation."""
    code = (
        "from importlib import import_module\n"
        "db_models = import_module('litestar_auth.authentication.strategy.db_models')\n"
        "from litestar_auth.authentication.strategy import import_token_orm_models\n"
        "from litestar_auth.models import import_token_orm_models as import_token_orm_models_from_models\n"
        "assert db_models.import_token_orm_models() == (db_models.AccessToken, db_models.RefreshToken)\n"
        "assert import_token_orm_models() == (db_models.AccessToken, db_models.RefreshToken)\n"
        "assert import_token_orm_models_from_models() == (db_models.AccessToken, db_models.RefreshToken)\n"
    )
    result = subprocess.run(
        [sys.executable, "-c", code],
        check=False,
        capture_output=True,
        text=True,
        timeout=60,
    )

    assert result.returncode == 0, (result.stdout, result.stderr)
