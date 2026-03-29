"""Integration tests for the SQLAlchemy user database adapter."""

from __future__ import annotations

import base64
import importlib
from typing import TYPE_CHECKING, Any, cast
from uuid import uuid4

import pytest
from advanced_alchemy.base import UUIDBase
from advanced_alchemy.exceptions import NotFoundError
from sqlalchemy import String, select
from sqlalchemy.orm import Mapped, mapped_column
from sqlalchemy.orm import Session as SASession

from litestar_auth.authentication.strategy.db_models import AccessToken
from litestar_auth.db import BaseOAuthAccountStore, BaseUserStore, SQLAlchemyUserDatabase
from litestar_auth.db.sqlalchemy import _build_user_repository
from litestar_auth.exceptions import OAuthAccountAlreadyLinkedError
from litestar_auth.models import OAuthAccount, User
from litestar_auth.oauth_encryption import (
    clear_oauth_token_encryption_key,
    oauth_token_encryption_scope,
    register_oauth_token_encryption_key,
)

if TYPE_CHECKING:
    from collections.abc import Iterable, Mapping, Sequence

    from sqlalchemy.engine import Connection, Engine
    from sqlalchemy.ext.asyncio import AsyncSession
    from sqlalchemy.orm.session import ForUpdateParameter
    from sqlalchemy.schema import MetaData
    from sqlalchemy.sql.base import Executable

    from litestar_auth.db.sqlalchemy import SQLAlchemyUserModelProtocol

pytestmark = pytest.mark.integration

_ = AccessToken
EXPECTED_TOTAL_USERS = 3


class MyUser(UUIDBase):
    """Custom user model with an extra profile field."""

    __tablename__ = "my_user"

    email: Mapped[str] = mapped_column(String(length=320), unique=True, index=True)
    hashed_password: Mapped[str] = mapped_column(String(length=255))
    is_active: Mapped[bool] = mapped_column(default=True, nullable=False)
    is_verified: Mapped[bool] = mapped_column(default=False, nullable=False)
    is_superuser: Mapped[bool] = mapped_column(default=False, nullable=False)
    totp_secret: Mapped[str | None] = mapped_column(String(length=255), default=None, nullable=True)
    bio: Mapped[str] = mapped_column(String(length=255), default="", nullable=False)


class AsyncSessionAdapter:
    """Minimal async adapter over a sync SQLAlchemy session for repository tests."""

    def __init__(self, session: SASession) -> None:
        """Store the wrapped session."""
        self._session = session
        self.info: dict[str, Any] = {}

    @property
    def bind(self) -> Engine | Connection | None:
        """Expose the wrapped session bind."""
        return cast("Engine | Connection | None", self._session.bind)

    def get_bind(self) -> Engine | Connection:
        """Expose the wrapped session bind via SQLAlchemy's API.

        Returns:
            Bound SQLAlchemy connectable.
        """
        return cast("Engine | Connection", self._session.get_bind())

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
    return User.metadata, MyUser.metadata


def create_database[UP: SQLAlchemyUserModelProtocol](
    session: SASession,
    *,
    user_model: type[UP] | None = None,
) -> SQLAlchemyUserDatabase[UP]:
    """Create a SQLAlchemyUserDatabase backed by the adapter session.

    Returns:
        Configured SQLAlchemy user database adapter.
    """
    adapter = cast("AsyncSession", AsyncSessionAdapter(session))
    return SQLAlchemyUserDatabase(session=adapter, user_model=user_model)


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

    with pytest.raises(ValueError, match="Lookup by 'totp_secret' is not permitted"):
        await database.get_by_field("totp_secret", "secret")


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


async def test_sqlalchemy_user_database_upsert_oauth_account_create(session: SASession) -> None:
    """upsert_oauth_account creates a new OAuthAccount when none exists."""
    database = create_database(session)
    user = await database.create(
        {"email": "upsert-create@example.com", "hashed_password": "hashed"},
    )
    scope = object()
    oauth_token_encryption_key = base64.urlsafe_b64encode(b"0" * 32).decode()
    register_oauth_token_encryption_key(scope, oauth_token_encryption_key)
    try:
        with oauth_token_encryption_scope(scope):
            await database.upsert_oauth_account(
                user,
                oauth_name="github",
                account_id="gh-1",
                account_email=user.email,
                access_token="at-1",
                expires_at=3600,
                refresh_token="rt-1",
            )
    finally:
        clear_oauth_token_encryption_key(scope)

    resolved = await database.get_by_oauth_account("github", "gh-1")
    assert resolved is not None
    assert resolved.id == user.id


async def test_sqlalchemy_user_database_upsert_oauth_account_update(session: SASession) -> None:
    """upsert_oauth_account updates existing OAuthAccount (email, tokens) without duplicating."""
    database = create_database(session)
    user = await database.create(
        {"email": "upsert-update@example.com", "hashed_password": "hashed"},
    )
    scope = object()
    oauth_token_encryption_key = base64.urlsafe_b64encode(b"0" * 32).decode()
    register_oauth_token_encryption_key(scope, oauth_token_encryption_key)
    try:
        with oauth_token_encryption_scope(scope):
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
    finally:
        clear_oauth_token_encryption_key(scope)


async def test_sqlalchemy_user_database_upsert_oauth_account_rejects_cross_user_rebinding(
    session: SASession,
) -> None:
    """upsert_oauth_account raises OAuthAccountAlreadyLinkedError when provider identity is already linked to another user."""
    database = create_database(session)
    user_a = await database.create(
        {"email": "user-a-oauth@example.com", "hashed_password": "hashed"},
    )
    user_b = await database.create(
        {"email": "user-b-oauth@example.com", "hashed_password": "hashed"},
    )
    scope = object()
    oauth_token_encryption_key = base64.urlsafe_b64encode(b"0" * 32).decode()
    register_oauth_token_encryption_key(scope, oauth_token_encryption_key)
    try:
        with oauth_token_encryption_scope(scope):
            await database.upsert_oauth_account(
                user_a,
                oauth_name="google",
                account_id="shared-id",
                account_email=user_a.email,
                access_token="at-a",
                expires_at=3600,
                refresh_token="rt-a",
            )
            with pytest.raises(OAuthAccountAlreadyLinkedError):
                await database.upsert_oauth_account(
                    user_b,
                    oauth_name="google",
                    account_id="shared-id",
                    account_email=user_b.email,
                    access_token="at-b",
                    expires_at=3600,
                    refresh_token="rt-b",
                )
            resolved = await database.get_by_oauth_account("google", "shared-id")
            assert resolved is not None
            assert resolved.id == user_a.id
    finally:
        clear_oauth_token_encryption_key(scope)


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
