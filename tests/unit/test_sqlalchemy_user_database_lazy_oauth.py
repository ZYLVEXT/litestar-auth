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


def test_oauth_account_model_without_declared_user_contract_is_allowed() -> None:
    """Contract validation skips OAuth models that do not declare user/table hooks yet."""

    class OpaqueOAuthAccount:
        pass

    session = MagicMock()
    database = SQLAlchemyUserDatabase(
        session=session,
        user_model=User,
        oauth_account_model=OpaqueOAuthAccount,
    )

    assert database._require_oauth_account_model() is OpaqueOAuthAccount


def test_oauth_account_model_rejects_different_declarative_registry() -> None:
    """Matching user/table names are insufficient when registries differ."""

    class RegistryMismatchOAuthAccount:
        auth_user_model = "User"
        auth_user_table = "user"
        registry = object()

    with pytest.raises(TypeError, match="different declarative registries"):
        SQLAlchemyUserDatabase(
            session=MagicMock(),
            user_model=User,
            oauth_account_model=RegistryMismatchOAuthAccount,
        )


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
def test_oauth_submodule_model_rejects_incompatible_custom_user_without_loading_reference_user() -> None:
    """The adapter rejects bundled OAuth wiring that targets a different custom user contract."""
    code = (
        "import sys\n"
        "from unittest.mock import MagicMock\n"
        "from advanced_alchemy.base import UUIDPrimaryKey, create_registry\n"
        "from sqlalchemy.orm import DeclarativeBase\n"
        "from litestar_auth.db.sqlalchemy import SQLAlchemyUserDatabase\n"
        "from litestar_auth.models import UserAuthRelationshipMixin, UserModelMixin\n"
        "from litestar_auth.models.oauth import OAuthAccount\n"
        "assert 'litestar_auth.models.user' not in sys.modules\n"
        "class AppBase(DeclarativeBase):\n"
        "    registry = create_registry()\n"
        "    metadata = registry.metadata\n"
        "    __abstract__ = True\n"
        "class AppUUIDBase(UUIDPrimaryKey, AppBase):\n"
        "    __abstract__ = True\n"
        "class CustomUser(UserModelMixin, UserAuthRelationshipMixin, AppUUIDBase):\n"
        "    __tablename__ = 'custom_user'\n"
        "    auth_access_token_model = None\n"
        "    auth_refresh_token_model = None\n"
        "    auth_oauth_account_model = None\n"
        "try:\n"
        "    SQLAlchemyUserDatabase(\n"
        "        session=MagicMock(),\n"
        "        user_model=CustomUser,\n"
        "        oauth_account_model=OAuthAccount,\n"
        "    )\n"
        "except TypeError as exc:\n"
        "    message = str(exc)\n"
        "else:\n"
        "    raise AssertionError('Expected TypeError for mismatched OAuth model contract')\n"
        "assert 'oauth_account_model does not match user_model' in message\n"
        "assert \"same-registry User mapped to the 'user' table\" in message\n"
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


@pytest.mark.imports
def test_sqlalchemy_user_database_supports_password_column_name_hook_without_reference_models() -> None:
    """The adapter accepts the supported password-column hook without loading reference models."""
    code = (
        "import sys\n"
        "from unittest.mock import MagicMock\n"
        "from advanced_alchemy.base import UUIDPrimaryKey, create_registry\n"
        "from sqlalchemy import inspect\n"
        "from sqlalchemy.orm import DeclarativeBase\n"
        "from litestar_auth.db.sqlalchemy import SQLAlchemyUserDatabase\n"
        "from litestar_auth.models import OAuthAccountMixin, UserAuthRelationshipMixin, UserModelMixin\n"
        "assert 'litestar_auth.models.user' not in sys.modules\n"
        "assert 'litestar_auth.models.oauth' not in sys.modules\n"
        "class AppBase(DeclarativeBase):\n"
        "    registry = create_registry()\n"
        "    metadata = registry.metadata\n"
        "    __abstract__ = True\n"
        "class AppUUIDBase(UUIDPrimaryKey, AppBase):\n"
        "    __abstract__ = True\n"
        "class LegacyUser(UserModelMixin, UserAuthRelationshipMixin, AppUUIDBase):\n"
        "    __tablename__ = 'legacy_user'\n"
        "    auth_access_token_model = None\n"
        "    auth_refresh_token_model = None\n"
        "    auth_oauth_account_model = 'LegacyOAuthAccount'\n"
        "    auth_hashed_password_column_name = 'password_hash'\n"
        "class LegacyOAuthAccount(OAuthAccountMixin, AppUUIDBase):\n"
        "    __tablename__ = 'legacy_oauth_account'\n"
        "    auth_user_model = 'LegacyUser'\n"
        "    auth_user_table = 'legacy_user'\n"
        "database = SQLAlchemyUserDatabase(\n"
        "    session=MagicMock(),\n"
        "    user_model=LegacyUser,\n"
        "    oauth_account_model=LegacyOAuthAccount,\n"
        ")\n"
        "assert database.user_model is LegacyUser\n"
        "assert database._require_oauth_account_model() is LegacyOAuthAccount\n"
        "assert inspect(LegacyUser).attrs.hashed_password.columns[0].name == 'password_hash'\n"
        "assert inspect(LegacyOAuthAccount).relationships['user'].mapper.class_ is LegacyUser\n"
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
