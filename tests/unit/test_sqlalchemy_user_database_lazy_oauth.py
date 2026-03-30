"""Unit tests for OAuth model requirement on ``SQLAlchemyUserDatabase``."""

from __future__ import annotations

from unittest.mock import MagicMock

import pytest

from litestar_auth.db.sqlalchemy import SQLAlchemyUserDatabase
from litestar_auth.models import OAuthAccount, User

pytestmark = pytest.mark.unit


def test_oauth_methods_raise_without_oauth_account_model() -> None:
    """OAuth methods raise ``TypeError`` when ``oauth_account_model`` is not configured."""
    session = MagicMock()
    database = SQLAlchemyUserDatabase(session=session, user_model=User)
    assert database.oauth_account_model is None
    with pytest.raises(TypeError, match="OAuth methods require oauth_account_model"):
        database._require_oauth_account_model()


def test_oauth_account_model_returned_when_set() -> None:
    """When ``oauth_account_model`` is passed, it is stored and returned."""
    session = MagicMock()
    database = SQLAlchemyUserDatabase(
        session=session,
        user_model=User,
        oauth_account_model=OAuthAccount,
    )
    assert database._require_oauth_account_model() is OAuthAccount
