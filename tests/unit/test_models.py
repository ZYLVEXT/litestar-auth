"""Tests for SQLAlchemy user, OAuth, access-token, and refresh-token models."""

from __future__ import annotations

import sqlite3
from typing import TYPE_CHECKING
from uuid import UUID

import pytest
from sqlalchemy import create_engine, event, inspect
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session
from sqlalchemy.pool import StaticPool

from litestar_auth.authentication.strategy.db_models import AccessToken, RefreshToken
from litestar_auth.models import OAuthAccount, User

if TYPE_CHECKING:
    from sqlalchemy.engine import Engine

pytestmark = pytest.mark.unit


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
