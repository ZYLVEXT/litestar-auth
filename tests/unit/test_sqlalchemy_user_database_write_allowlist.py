"""Unit tests for the persistence-side write allow-list on ``SQLAlchemyUserDatabase``."""

from __future__ import annotations

from unittest.mock import MagicMock

import pytest

from litestar_auth.db.sqlalchemy import SQLAlchemyUserDatabase, _collect_writable_user_fields
from litestar_auth.models import User

pytestmark = pytest.mark.unit


def test_collect_writable_user_fields_includes_columns_relationships_and_property_setters() -> None:
    """The allow-list covers mapper attributes plus class-level setter properties.

    ``email`` is a mapped column, ``role_assignments`` is a SQLAlchemy
    relationship, and ``roles`` is a Python ``@property`` with a setter that
    delegates into ``role_assignments``. All three must be writable so that
    custom user models with computed setter properties keep working.
    """
    fields = _collect_writable_user_fields(User)

    assert "email" in fields
    assert "hashed_password" in fields
    assert "role_assignments" in fields
    assert "roles" in fields


def test_collect_writable_user_fields_omits_arbitrary_python_attributes() -> None:
    """Names without a column, relationship, or setter property are excluded.

    Without this exclusion, ``setattr`` on the persistent user could silently
    create unmapped instance attributes that look successful but never reach
    the database, hiding bugs and giving callers a false sense of write success.
    """
    fields = _collect_writable_user_fields(User)

    assert "totally_unmapped_attribute" not in fields
    assert "__class__" not in fields


async def test_sqlalchemy_user_database_update_rejects_unmapped_field() -> None:
    """``update`` raises before touching the session when given an unmapped field."""
    session = MagicMock()
    database = SQLAlchemyUserDatabase(session=session, user_model=User)
    user = MagicMock()

    with pytest.raises(ValueError, match=r"rejected fields not on 'User'"):
        await database.update(user, {"definitely_not_a_field": "x"})
    session.merge.assert_not_called()


async def test_sqlalchemy_user_database_update_error_lists_offending_fields_sorted() -> None:
    """Failure messages enumerate every unknown field in deterministic order."""
    session = MagicMock()
    database = SQLAlchemyUserDatabase(session=session, user_model=User)
    user = MagicMock()

    with pytest.raises(ValueError, match="rejected fields not on") as exc_info:
        await database.update(user, {"zeta": 1, "alpha": 2})
    message = str(exc_info.value)
    assert "'alpha'" in message
    assert "'zeta'" in message
    assert message.index("'alpha'") < message.index("'zeta'")
