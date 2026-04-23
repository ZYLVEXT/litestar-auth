"""Integration tests for the SQLAlchemy user database adapter."""

from __future__ import annotations

import base64
import importlib
from typing import TYPE_CHECKING, Any, cast
from uuid import uuid4

import pytest
from advanced_alchemy.base import UUIDBase, UUIDPrimaryKey, create_registry
from advanced_alchemy.exceptions import NotFoundError
from sqlalchemy import String, inspect, select
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column
from sqlalchemy.orm import Session as SASession

from litestar_auth.authentication.strategy.db_models import AccessToken
from litestar_auth.db import BaseOAuthAccountStore, BaseUserStore
from litestar_auth.db.sqlalchemy import (
    SQLAlchemyUserDatabase,
    _build_oauth_repository,
    _build_user_load,
    _build_user_repository,
)
from litestar_auth.exceptions import ConfigurationError, OAuthAccountAlreadyLinkedError
from litestar_auth.models import (
    AccessTokenMixin,
    OAuthAccount,
    OAuthAccountMixin,
    RefreshTokenMixin,
    Role,
    User,
    UserAuthRelationshipMixin,
    UserModelMixin,
    UserRole,
)
from litestar_auth.oauth_encryption import OAuthTokenEncryption, bind_oauth_token_encryption
from litestar_auth.types import LoginIdentifier  # noqa: TC001

if TYPE_CHECKING:
    from collections.abc import Iterable, Mapping, Sequence

    from sqlalchemy.engine import Connection, Engine
    from sqlalchemy.ext.asyncio import AsyncSession
    from sqlalchemy.orm.session import ForUpdateParameter
    from sqlalchemy.schema import MetaData
    from sqlalchemy.sql.base import Executable


pytestmark = pytest.mark.integration

_ = AccessToken
EXPECTED_TOTAL_USERS = 3
_UNSET_OAUTH_TOKEN_ENCRYPTION = object()


class MyUser(UserModelMixin, UUIDBase):
    """Custom user model with an extra profile field."""

    __tablename__ = "my_user"

    bio: Mapped[str] = mapped_column(String(length=255), default="", nullable=False)


class CustomAuthBase(DeclarativeBase):
    """App-owned registry for mixin-composed auth models."""

    registry = create_registry()
    metadata = registry.metadata
    __abstract__ = True


class CustomUUIDBase(UUIDPrimaryKey, CustomAuthBase):
    """UUID primary-key base bound to the app-owned auth registry."""

    __abstract__ = True


class MyOAuthUser(UserModelMixin, UserAuthRelationshipMixin, CustomUUIDBase):
    """Custom user model composed for the OAuth-only mixin path."""

    __tablename__ = "my_oauth_user"

    auth_access_token_model = None
    auth_refresh_token_model = None
    auth_oauth_account_model = "MyOAuthAccount"


class MyOAuthAccount(OAuthAccountMixin, CustomUUIDBase):
    """Custom OAuth model composed from the supported library mixin."""

    __tablename__ = "my_oauth_account"

    auth_user_model = "MyOAuthUser"
    auth_user_table = "my_oauth_user"


class ConfiguredUser(UserModelMixin, UserAuthRelationshipMixin, CustomUUIDBase):
    """Custom user model that exercises relationship-option overrides without replacing inverse wiring."""

    __tablename__ = "configured_user"

    auth_access_token_model = "ConfiguredAccessToken"
    auth_refresh_token_model = "ConfiguredRefreshToken"
    auth_oauth_account_model = "ConfiguredOAuthAccount"
    auth_token_relationship_lazy = "noload"
    auth_oauth_account_relationship_lazy = "selectin"
    auth_oauth_account_relationship_foreign_keys = "ConfiguredOAuthAccount.user_id"


class ConfiguredAccessToken(AccessTokenMixin, CustomAuthBase):
    """Access-token model bound to the configured relationship-override user."""

    __tablename__ = "configured_access_token"

    auth_user_model = "ConfiguredUser"
    auth_user_table = "configured_user"


class ConfiguredRefreshToken(RefreshTokenMixin, CustomAuthBase):
    """Refresh-token model bound to the configured relationship-override user."""

    __tablename__ = "configured_refresh_token"

    auth_user_model = "ConfiguredUser"
    auth_user_table = "configured_user"


class ConfiguredOAuthAccount(OAuthAccountMixin, CustomUUIDBase):
    """OAuth-account model bound to the configured relationship-override user."""

    __tablename__ = "configured_oauth_account"

    auth_user_model = "ConfiguredUser"
    auth_user_table = "configured_user"


class AsyncSessionAdapter:
    """Minimal async adapter over a sync SQLAlchemy session for repository tests."""

    def __init__(self, session: SASession) -> None:
        """Store the wrapped session."""
        self._session = session
        self.info: dict[str, Any] = {}

    @property
    def bind(self) -> Engine | Connection | None:
        """Expose the wrapped session bind."""
        return self._session.bind

    def get_bind(self) -> Engine | Connection:
        """Expose the wrapped session bind via SQLAlchemy's API.

        Returns:
            Bound SQLAlchemy connectable.
        """
        return self._session.get_bind()

    @property
    def no_autoflush(self) -> object:
        """Expose the wrapped session no-autoflush context manager."""
        return self._session.no_autoflush

    def add(self, instance: object) -> None:
        """Add an instance to the session."""
        self._session.add(instance)

    def add_all(self, instances: Sequence[object]) -> None:
        """Add multiple instances to the session."""
        self._session.add_all(instances)

    def expunge(self, instance: object) -> None:
        """Expunge an instance from the session."""
        self._session.expunge(instance)

    async def commit(self) -> None:
        """Commit the current transaction."""
        self._session.commit()

    async def delete(self, instance: object) -> None:
        """Delete an instance from the session."""
        self._session.delete(instance)

    async def execute(
        self,
        statement: Executable,
        params: Mapping[str, object] | Sequence[Mapping[str, object]] | None = None,
        *,
        execution_options: Mapping[str, object] | None = None,
    ) -> object:
        """Execute a SQL statement.

        Returns:
            SQLAlchemy execution result.
        """
        sync_session = cast("Any", self._session)
        return cast("object", sync_session.execute(statement, params=params, execution_options=execution_options))

    async def flush(self) -> None:
        """Flush pending changes."""
        self._session.flush()

    async def merge(self, instance: object, *, load: bool = True) -> object:
        """Merge an instance into the session.

        Returns:
            The merged mapped instance.
        """
        return self._session.merge(instance, load=load)

    async def refresh(
        self,
        instance: object,
        *,
        attribute_names: Iterable[str] | None = None,
        with_for_update: ForUpdateParameter = None,
    ) -> None:
        """Refresh an instance from the database."""
        self._session.refresh(instance, attribute_names=attribute_names, with_for_update=with_for_update)


@pytest.fixture
def sqlalchemy_metadata() -> tuple[MetaData, ...]:
    """Create the shared auth tables together with the custom user table.

    Returns:
        Metadata collections that should be created for this module's session fixture.
    """
    return User.metadata, MyUser.metadata, MyOAuthUser.metadata


def create_database(
    session: SASession,
    *,
    user_model: type[Any] = User,
    oauth_account_model: type[Any] | None = None,
    oauth_token_encryption: OAuthTokenEncryption | object = _UNSET_OAUTH_TOKEN_ENCRYPTION,
) -> SQLAlchemyUserDatabase[Any]:
    """Create a SQLAlchemyUserDatabase backed by the adapter session.

    Returns:
        Configured SQLAlchemy user database adapter.
    """
    adapter = cast("AsyncSession", AsyncSessionAdapter(session))
    resolved_oauth_account_model = oauth_account_model
    if resolved_oauth_account_model is None and user_model is User:
        resolved_oauth_account_model = OAuthAccount
    if oauth_token_encryption is _UNSET_OAUTH_TOKEN_ENCRYPTION:
        return SQLAlchemyUserDatabase(
            session=adapter,
            user_model=user_model,
            oauth_account_model=resolved_oauth_account_model,
        )
    return SQLAlchemyUserDatabase(
        session=adapter,
        user_model=user_model,
        oauth_account_model=resolved_oauth_account_model,
        oauth_token_encryption=cast("OAuthTokenEncryption | None", oauth_token_encryption),
    )


def test_sqlalchemy_user_database_reuses_repository_type_per_model(session: SASession) -> None:
    """Dynamic user repository classes are cached per model — avoid repeated allocations."""
    db_a = create_database(session)
    db_b = create_database(session)
    assert db_a._user_repository_type is db_b._user_repository_type

    db_custom_1 = create_database(session, user_model=MyUser)
    db_custom_2 = create_database(session, user_model=MyUser)
    assert db_custom_1._user_repository_type is db_custom_2._user_repository_type
    assert db_custom_1._user_repository_type is not db_a._user_repository_type


def test_build_user_repository_returns_cached_repository_type() -> None:
    """The dynamic repository factory caches one repository class per user model."""
    user_repository = _build_user_repository(User)
    custom_repository = _build_user_repository(MyUser)

    assert user_repository is _build_user_repository(User)
    assert user_repository.model_type is User
    assert custom_repository is _build_user_repository(MyUser)
    assert custom_repository.model_type is MyUser
    assert custom_repository is not user_repository


def test_build_oauth_repository_returns_cached_repository_type() -> None:
    """The OAuth repository factory caches one repository class per OAuth model."""
    oauth_repository = _build_oauth_repository(OAuthAccount)

    assert oauth_repository is _build_oauth_repository(OAuthAccount)
    assert oauth_repository.model_type is OAuthAccount


def test_build_user_load_returns_empty_tuple_for_non_inspectable_models() -> None:
    """Non-SQLAlchemy user classes do not raise when load options are requested."""

    class PlainUser:
        """Deliberately unmapped class used to exercise the inspection fallback."""

    assert _build_user_load(cast("Any", PlainUser)) == ()


def test_custom_user_relationship_option_overrides_keep_mapper_contract_stable() -> None:
    """Custom relationship overrides keep inverse mapper wiring intact while exposing explicit relationship options."""
    configured_relationships = inspect(ConfiguredUser).relationships

    assert sorted(configured_relationships.keys()) == ["access_tokens", "oauth_accounts", "refresh_tokens"]
    assert configured_relationships["access_tokens"].mapper.class_ is ConfiguredAccessToken
    assert configured_relationships["access_tokens"].lazy == "noload"
    assert configured_relationships["access_tokens"]._user_defined_foreign_keys == set()
    assert configured_relationships["refresh_tokens"].mapper.class_ is ConfiguredRefreshToken
    assert configured_relationships["refresh_tokens"].lazy == "noload"
    assert configured_relationships["refresh_tokens"]._user_defined_foreign_keys == set()
    assert configured_relationships["oauth_accounts"].mapper.class_ is ConfiguredOAuthAccount
    assert configured_relationships["oauth_accounts"].lazy == "selectin"
    assert configured_relationships["oauth_accounts"]._user_defined_foreign_keys == {
        ConfiguredOAuthAccount.__table__.c.user_id,
    }
    assert inspect(ConfiguredAccessToken).relationships["user"].mapper.class_ is ConfiguredUser
    assert inspect(ConfiguredRefreshToken).relationships["user"].mapper.class_ is ConfiguredUser
    assert inspect(ConfiguredOAuthAccount).relationships["user"].mapper.class_ is ConfiguredUser


def test_sqlalchemy_module_reload_preserves_repository_factory_contract() -> None:
    """Reloading the module preserves the dynamic repository factory behavior."""
    sqlalchemy_module = importlib.import_module("litestar_auth.db.sqlalchemy")
    reloaded_module = importlib.reload(sqlalchemy_module)
    reloaded_repository = reloaded_module._build_user_repository(User)

    assert reloaded_repository is reloaded_module._build_user_repository(User)
    assert reloaded_repository.model_type is User


async def test_sqlalchemy_user_database_crud(session: SASession) -> None:
    """The SQLAlchemy adapter provides CRUD operations for users."""
    database = create_database(session)

    assert isinstance(database, BaseUserStore)
    assert isinstance(database, BaseOAuthAccountStore)

    created_user = await database.create(
        {
            "email": "sqlalchemy-db@example.com",
            "hashed_password": "hashed-password",
        },
    )

    fetched_by_id = await database.get(created_user.id)
    fetched_by_email = await database.get_by_email(created_user.email)

    assert fetched_by_id is not None
    assert fetched_by_email is not None
    fetched_by_field = await database.get_by_field("email", created_user.email)
    assert fetched_by_field is not None
    assert fetched_by_field.id == created_user.id
    assert fetched_by_id.id == created_user.id
    assert fetched_by_email.id == created_user.id
    assert created_user.is_active is True
    assert created_user.is_verified is False

    updated_user = await database.update(
        created_user,
        {
            "email": "sqlalchemy-db-updated@example.com",
            "is_verified": True,
            "totp_secret": "totp-secret",
        },
    )

    assert updated_user.email == "sqlalchemy-db-updated@example.com"
    assert updated_user.is_verified is True
    assert updated_user.totp_secret == "totp-secret"
    assert await database.get_by_email("sqlalchemy-db@example.com") is None

    await database.delete(updated_user.id)

    assert await database.get(updated_user.id) is None


async def test_sqlalchemy_user_database_crud_missing_paths(session: SASession) -> None:
    """Missing-user CRUD lookups return empty results and invalid lookups are rejected."""
    database = create_database(session)

    assert await database.get(uuid4()) is None
    assert await database.get_by_email("missing@example.com") is None
    assert await database.get_by_field("email", "missing@example.com") is None

    # Static typing restricts ``field_name`` to ``LoginIdentifier``; ``cast`` exercises
    # the SQLAlchemy allow-list ValueError as defense-in-depth for dynamic callers.
    with pytest.raises(ValueError, match="Lookup by 'totp_secret' is not permitted"):
        await database.get_by_field(cast("LoginIdentifier", "totp_secret"), "secret")


async def test_sqlalchemy_user_database_update_merges_detached_instances(session: SASession) -> None:
    """Updates succeed for detached user instances by merging them into the current session."""
    database = create_database(session)
    created_user = await database.create(
        {
            "email": "detached-update@example.com",
            "hashed_password": "hashed-password",
        },
    )
    session.expunge(created_user)

    updated_user = await database.update(
        created_user,
        {
            "email": "detached-update-changed@example.com",
            "is_active": False,
        },
    )

    assert updated_user.email == "detached-update-changed@example.com"
    assert updated_user.is_active is False
    resolved_user = await database.get(updated_user.id)
    assert resolved_user is not None
    assert resolved_user.email == "detached-update-changed@example.com"
    assert resolved_user.is_active is False


async def test_sqlalchemy_user_database_hydrates_relation_backed_roles_on_create_and_lookup(session: SASession) -> None:
    """Create and lookup paths return users whose role snapshots survive session detachment."""
    database = create_database(session)

    created_user = await database.create(
        {
            "email": "role-create@example.com",
            "hashed_password": "hashed-password",
            "roles": [" Billing ", "ADMIN", "admin"],
        },
    )
    fetched_by_id = await database.get(created_user.id)
    fetched_by_email = await database.get_by_email(created_user.email)
    fetched_by_field = await database.get_by_field("email", created_user.email)

    assert fetched_by_id is not None
    assert fetched_by_email is not None
    assert fetched_by_field is not None
    session.expunge_all()
    assert created_user.roles == ["admin", "billing"]
    assert fetched_by_id.roles == ["admin", "billing"]
    assert fetched_by_email.roles == ["admin", "billing"]
    assert fetched_by_field.roles == ["admin", "billing"]
    assert list(session.execute(select(Role.name).order_by(Role.name)).scalars()) == ["admin", "billing"]
    assert list(
        session.execute(
            select(UserRole.role_name).where(UserRole.user_id == created_user.id).order_by(UserRole.role_name),
        ).scalars(),
    ) == ["admin", "billing"]


async def test_sqlalchemy_user_database_update_replaces_role_assignments_without_duplicates(session: SASession) -> None:
    """Updating roles replaces association rows deterministically and keeps the flat list contract."""
    database = create_database(session)
    created_user = await database.create(
        {
            "email": "role-update@example.com",
            "hashed_password": "hashed-password",
            "roles": ["member"],
        },
    )
    session.expunge(created_user)

    updated_user = await database.update(
        created_user,
        {
            "roles": [" Support ", "admin", "ADMIN"],
        },
    )
    refreshed_user = await database.get(updated_user.id)

    assert refreshed_user is not None
    # Returned instance must have hydrated role_assignments (not a second SELECT via reload).
    assert {a.role_name for a in updated_user.role_assignments} == {"admin", "support"}
    session.expunge_all()
    assert updated_user.roles == ["admin", "support"]
    assert refreshed_user.roles == ["admin", "support"]
    assert list(
        session.execute(
            select(UserRole.role_name).where(UserRole.user_id == updated_user.id).order_by(UserRole.role_name),
        ).scalars(),
    ) == ["admin", "support"]
    assert list(session.execute(select(Role.name).order_by(Role.name)).scalars()) == ["admin", "member", "support"]


async def test_sqlalchemy_user_database_list_users(session: SASession) -> None:
    """The SQLAlchemy adapter returns paginated users with a total count."""
    database = create_database(session)
    emails = [
        "page-user-1@example.com",
        "page-user-2@example.com",
        "page-user-3@example.com",
    ]
    for email in emails:
        await database.create({"email": email, "hashed_password": f"hash-{email}"})

    users, total = await database.list_users(offset=1, limit=1)

    assert total == EXPECTED_TOTAL_USERS
    assert len(users) == 1
    assert users[0].email == "page-user-2@example.com"


async def test_sqlalchemy_user_database_list_users_hydrates_role_membership(session: SASession) -> None:
    """Paginated user listings can expose relation-backed role membership after detachment."""
    database = create_database(session)
    for index, roles in enumerate((["admin"], ["member"], ["support"]), start=1):
        await database.create(
            {
                "email": f"roles-page-{index}@example.com",
                "hashed_password": f"hash-{index}",
                "roles": roles,
            },
        )

    users, total = await database.list_users(offset=0, limit=10)

    assert total == EXPECTED_TOTAL_USERS
    session.expunge_all()
    assert sorted((user.email, user.roles) for user in users) == [
        ("roles-page-1@example.com", ["admin"]),
        ("roles-page-2@example.com", ["member"]),
        ("roles-page-3@example.com", ["support"]),
    ]


async def test_sqlalchemy_user_database_list_users_empty_page(session: SASession) -> None:
    """Out-of-range pages return an empty page and Advanced Alchemy's current count result."""
    database = create_database(session)
    for email in ("edge-page-1@example.com", "edge-page-2@example.com"):
        await database.create({"email": email, "hashed_password": f"hash-{email}"})

    users, total = await database.list_users(offset=5, limit=2)

    assert users == []
    assert total == 0


async def test_sqlalchemy_user_database_get_by_oauth_account(session: SASession) -> None:
    """OAuth account lookups return the linked user."""
    database = create_database(session)
    bind_oauth_token_encryption(
        session,
        OAuthTokenEncryption(base64.urlsafe_b64encode(b"3" * 32).decode()),
    )
    user = await database.create(
        {
            "email": "oauth-db@example.com",
            "hashed_password": "hashed-password",
        },
    )
    oauth_account = OAuthAccount(
        user_id=user.id,
        oauth_name="github",
        account_id="github-user-1",
        account_email=user.email,
        access_token="github-access-token",
    )
    session.add(oauth_account)
    session.commit()

    resolved_user = await database.get_by_oauth_account("github", "github-user-1")

    assert resolved_user is not None
    assert resolved_user.id == user.id
    assert await database.get_by_oauth_account("github", "missing") is None


async def test_sqlalchemy_user_database_custom_oauth_model_mixin_contract(session: SASession) -> None:
    """The adapter supports a custom OAuth model composed from the library mixin."""
    database = create_database(
        session,
        user_model=MyOAuthUser,
        oauth_account_model=MyOAuthAccount,
        oauth_token_encryption=OAuthTokenEncryption(base64.urlsafe_b64encode(b"1" * 32).decode()),
    )
    user = await database.create(
        {
            "email": "custom-oauth@example.com",
            "hashed_password": "hashed-password",
        },
    )
    await database.upsert_oauth_account(
        user,
        oauth_name="github",
        account_id="custom-gh-1",
        account_email=user.email,
        access_token="custom-access-token",
        expires_at=3_600,
        refresh_token="custom-refresh-token",
    )

    resolved_user = await database.get_by_oauth_account("github", "custom-gh-1")
    assert resolved_user is not None
    assert isinstance(resolved_user, MyOAuthUser)
    assert resolved_user.id == user.id

    oauth_accounts = list(session.execute(select(MyOAuthAccount)).scalars().all())
    assert len(oauth_accounts) == 1
    oauth_account = oauth_accounts[0]
    assert isinstance(oauth_account, MyOAuthAccount)
    assert oauth_account.user_id == user.id
    assert oauth_account.user is user
    assert list(user.oauth_accounts) == [oauth_account]


def test_sqlalchemy_user_database_rejects_mismatched_oauth_model_contract(session: SASession) -> None:
    """The adapter fails fast when bundled OAuth wiring targets a different custom user contract."""
    with pytest.raises(TypeError, match="oauth_account_model does not match user_model"):
        create_database(session, user_model=MyUser, oauth_account_model=OAuthAccount)


async def test_sqlalchemy_user_database_supports_relationship_option_override_models(session: SASession) -> None:
    """The adapter supports custom user models that override relationship loader options and OAuth foreign keys."""
    configured_relationships = inspect(ConfiguredUser).relationships

    assert configured_relationships["access_tokens"].lazy == "noload"
    assert configured_relationships["refresh_tokens"].lazy == "noload"
    assert configured_relationships["oauth_accounts"].lazy == "selectin"
    assert configured_relationships["oauth_accounts"]._user_defined_foreign_keys == {
        ConfiguredOAuthAccount.__table__.c.user_id,
    }

    database = create_database(
        session,
        user_model=ConfiguredUser,
        oauth_account_model=ConfiguredOAuthAccount,
        oauth_token_encryption=OAuthTokenEncryption(base64.urlsafe_b64encode(b"2" * 32).decode()),
    )
    user = await database.create(
        {
            "email": "configured-oauth@example.com",
            "hashed_password": "hashed-password",
        },
    )
    await database.upsert_oauth_account(
        user,
        oauth_name="github",
        account_id="configured-gh-1",
        account_email=user.email,
        access_token="configured-access-token",
        expires_at=7_200,
        refresh_token="configured-refresh-token",
    )

    resolved_user = await database.get_by_oauth_account("github", "configured-gh-1")
    assert resolved_user is not None
    assert isinstance(resolved_user, ConfiguredUser)
    assert resolved_user.id == user.id

    oauth_accounts = list(session.execute(select(ConfiguredOAuthAccount)).scalars().all())
    assert len(oauth_accounts) == 1
    oauth_account = oauth_accounts[0]
    assert isinstance(oauth_account, ConfiguredOAuthAccount)
    assert oauth_account.user_id == user.id
    assert oauth_account.user is user


async def test_sqlalchemy_user_database_upsert_oauth_account_create(session: SASession) -> None:
    """upsert_oauth_account creates a new OAuthAccount when none exists."""
    oauth_token_encryption = OAuthTokenEncryption(base64.urlsafe_b64encode(b"0" * 32).decode())
    database = create_database(session, oauth_token_encryption=oauth_token_encryption)
    user = await database.create(
        {"email": "upsert-create@example.com", "hashed_password": "hashed"},
    )
    await database.upsert_oauth_account(
        user,
        oauth_name="github",
        account_id="gh-1",
        account_email=user.email,
        access_token="at-1",
        expires_at=3600,
        refresh_token="rt-1",
    )

    resolved = await database.get_by_oauth_account("github", "gh-1")
    assert resolved is not None
    assert resolved.id == user.id
    stored_access_token, stored_refresh_token = session.execute(
        select(
            OAuthAccount.__table__.c.access_token,
            OAuthAccount.__table__.c.refresh_token,
        ).where(OAuthAccount.__table__.c.user_id == user.id),
    ).one()
    assert stored_access_token != "at-1"
    assert stored_refresh_token != "rt-1"


async def test_sqlalchemy_user_database_upsert_oauth_account_requires_explicit_encryption_policy(
    session: SASession,
) -> None:
    """OAuth token writes fail closed until a direct adapter receives an explicit policy."""
    database = create_database(session)
    user = await database.create({"email": "missing-oauth-policy@example.com", "hashed_password": "hashed"})

    with pytest.raises(ConfigurationError, match="OAuth token writes require oauth_token_encryption"):
        await database.upsert_oauth_account(
            user,
            oauth_name="github",
            account_id="missing-policy",
            account_email=user.email,
            access_token="token",
            expires_at=60,
            refresh_token=None,
        )


async def test_sqlalchemy_user_database_upsert_oauth_account_update(session: SASession) -> None:
    """upsert_oauth_account updates existing OAuthAccount (email, tokens) without duplicating."""
    database = create_database(
        session,
        oauth_token_encryption=OAuthTokenEncryption(base64.urlsafe_b64encode(b"0" * 32).decode()),
    )
    user = await database.create(
        {"email": "upsert-update@example.com", "hashed_password": "hashed"},
    )
    await database.upsert_oauth_account(
        user,
        oauth_name="google",
        account_id="go-1",
        account_email="first@example.com",
        access_token="at-old",
        expires_at=1800,
        refresh_token="rt-old",
    )

    await database.upsert_oauth_account(
        user,
        oauth_name="google",
        account_id="go-1",
        account_email="updated@example.com",
        access_token="at-new",
        expires_at=7200,
        refresh_token="rt-new",
    )

    resolved = await database.get_by_oauth_account("google", "go-1")
    assert resolved is not None
    assert resolved.id == user.id
    result = session.execute(select(OAuthAccount).where(OAuthAccount.user_id == user.id))
    oauth_accounts = list(result.scalars().all())
    assert len(oauth_accounts) == 1
    oauth_account = oauth_accounts[0]
    expected_expires_at = 7200
    assert oauth_account.account_email == "updated@example.com"
    assert oauth_account.access_token == "at-new"
    assert oauth_account.expires_at == expected_expires_at
    assert oauth_account.refresh_token == "rt-new"


async def test_sqlalchemy_user_database_upsert_oauth_account_rejects_cross_user_rebinding(
    session: SASession,
) -> None:
    """upsert_oauth_account raises OAuthAccountAlreadyLinkedError when provider identity is already linked to another user."""
    database = create_database(
        session,
        oauth_token_encryption=OAuthTokenEncryption(base64.urlsafe_b64encode(b"0" * 32).decode()),
    )
    user_a = await database.create(
        {"email": "user-a-oauth@example.com", "hashed_password": "hashed"},
    )
    user_b = await database.create(
        {"email": "user-b-oauth@example.com", "hashed_password": "hashed"},
    )
    await database.upsert_oauth_account(
        user_a,
        oauth_name="google",
        account_id="shared-id",
        account_email=user_a.email,
        access_token="at-a",
        expires_at=3600,
        refresh_token="rt-a",
    )
    with pytest.raises(OAuthAccountAlreadyLinkedError) as exc_info:
        await database.upsert_oauth_account(
            user_b,
            oauth_name="google",
            account_id="shared-id",
            account_email=user_b.email,
            access_token="at-b",
            expires_at=3600,
            refresh_token="rt-b",
        )
    assert exc_info.value.provider == "google"
    assert exc_info.value.account_id == "shared-id"
    assert exc_info.value.existing_user_id == user_a.id
    assert str(exc_info.value) == f"OAuth account google:shared-id is already linked to user {user_a.id}"
    resolved = await database.get_by_oauth_account("google", "shared-id")
    assert resolved is not None
    assert resolved.id == user_a.id


async def test_sqlalchemy_user_database_delete_missing_user_raises_not_found(session: SASession) -> None:
    """Deleting an unknown user surfaces the repository's not-found behavior."""
    database = create_database(session)

    with pytest.raises(NotFoundError):
        await database.delete(uuid4())


async def test_sqlalchemy_user_database_custom_model(session: SASession) -> None:
    """The adapter can persist a custom UUIDBase user model."""
    database = create_database(session, user_model=MyUser)

    created_user = await database.create(
        {
            "email": "custom-model@example.com",
            "hashed_password": "hashed-password",
            "bio": "Custom profile",
        },
    )

    assert isinstance(created_user, MyUser)
    assert created_user.bio == "Custom profile"

    fetched_user = await database.get(created_user.id)
    assert fetched_user is not None
    assert isinstance(fetched_user, MyUser)
    assert fetched_user.bio == "Custom profile"

    updated_user = await database.update(created_user, {"bio": "Updated profile"})

    assert updated_user.bio == "Updated profile"
    assert await database.get_by_email("custom-model@example.com") is not None
