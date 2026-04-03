"""Unit tests for OAuth model requirement on ``SQLAlchemyUserDatabase``."""

from __future__ import annotations

import subprocess
import sys
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


@pytest.mark.imports
def test_user_relationship_mixin_can_pair_custom_user_with_library_oauth_account() -> None:
    """Custom users can adopt the shared relationship contract and still wire the library OAuth model."""
    code = (
        "import sys\n"
        "from unittest.mock import MagicMock\n"
        "from advanced_alchemy.base import UUIDBase\n"
        "from sqlalchemy import String, inspect\n"
        "from sqlalchemy.orm import Mapped, mapped_column\n"
        "from litestar_auth.db.sqlalchemy import SQLAlchemyUserDatabase\n"
        "from litestar_auth.models.oauth import OAuthAccount\n"
        "from litestar_auth.models.user_relationships import UserAuthRelationshipMixin\n"
        "assert 'litestar_auth.models.user' not in sys.modules\n"
        "class User(UserAuthRelationshipMixin, UUIDBase):\n"
        "    __tablename__ = 'user'\n"
        "    email: Mapped[str] = mapped_column(String(length=320), unique=True, index=True)\n"
        "    hashed_password: Mapped[str] = mapped_column(String(length=255))\n"
        "    is_active: Mapped[bool] = mapped_column(default=True, nullable=False)\n"
        "    is_verified: Mapped[bool] = mapped_column(default=False, nullable=False)\n"
        "    is_superuser: Mapped[bool] = mapped_column(default=False, nullable=False)\n"
        "    totp_secret: Mapped[str | None] = mapped_column(String(length=255), default=None, nullable=True)\n"
        "database = SQLAlchemyUserDatabase(\n"
        "    session=MagicMock(),\n"
        "    user_model=User,\n"
        "    oauth_account_model=OAuthAccount,\n"
        ")\n"
        "assert database._require_oauth_account_model() is OAuthAccount\n"
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
def test_oauth_submodule_model_can_configure_adapter_without_loading_reference_user() -> None:
    """The adapter accepts ``models.oauth.OAuthAccount`` without importing the bundled ``User`` model."""
    code = (
        "import sys\n"
        "from unittest.mock import MagicMock\n"
        "from litestar_auth.db.sqlalchemy import SQLAlchemyUserDatabase\n"
        "from litestar_auth.models.oauth import OAuthAccount\n"
        "class CustomUserModel:\n"
        "    pass\n"
        "database = SQLAlchemyUserDatabase(\n"
        "    session=MagicMock(),\n"
        "    user_model=CustomUserModel,\n"
        "    oauth_account_model=OAuthAccount,\n"
        ")\n"
        "assert database._require_oauth_account_model() is OAuthAccount\n"
        'assert "litestar_auth.models.user" not in sys.modules\n'
    )
    result = subprocess.run(
        [sys.executable, "-c", code],
        check=False,
        capture_output=True,
        text=True,
        timeout=60,
    )

    assert result.returncode == 0, (result.stdout, result.stderr)
