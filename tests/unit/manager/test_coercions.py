"""Unit tests for internal manager coercion helpers."""

from __future__ import annotations

import importlib
from unittest.mock import patch
from uuid import uuid4

import msgspec
import pytest

import litestar_auth._manager._coercions as coercions_module
from litestar_auth._manager._coercions import _account_state_user, _as_dict, _managed_user, _require_str
from tests._helpers import ExampleUser

pytestmark = pytest.mark.unit


class RegistrationPayload(msgspec.Struct):
    """Simple struct payload for coercion tests."""

    email: str
    password: str


def test_coercions_module_executes_under_coverage() -> None:
    """Reload the module in-test so coverage records module execution."""
    reloaded_module = importlib.reload(coercions_module)

    assert reloaded_module._as_dict.__name__ == _as_dict.__name__
    assert reloaded_module._require_str.__name__ == _require_str.__name__
    assert reloaded_module._managed_user.__name__ == _managed_user.__name__
    assert reloaded_module._account_state_user.__name__ == _account_state_user.__name__


def test_as_dict_accepts_mapping() -> None:
    """Mappings are copied into plain dictionaries unchanged."""
    assert _as_dict({"email": "user@example.com"}) == {"email": "user@example.com"}


def test_as_dict_accepts_msgspec_struct() -> None:
    """Msgspec structs are converted into plain dictionaries."""
    payload = RegistrationPayload(email="user@example.com", password="secret")

    assert _as_dict(payload) == {"email": "user@example.com", "password": "secret"}


def test_as_dict_raises_when_struct_conversion_is_not_a_dict() -> None:
    """The defensive guard rejects unexpected msgspec conversions."""
    payload = RegistrationPayload(email="user@example.com", password="secret")

    with (
        patch.object(coercions_module.msgspec, "to_builtins", return_value=["not", "a", "dict"]),
        pytest.raises(TypeError, match="msgspec struct conversion must yield a dict"),
    ):
        _as_dict(payload)


def test_require_str_returns_string_values() -> None:
    """Required string fields are returned unchanged."""
    assert _require_str({"email": "user@example.com"}, "email") == "user@example.com"


@pytest.mark.parametrize("data", [{}, {"email": 123}], ids=["missing_field", "non_string_value"])
def test_require_str_raises_when_field_missing_or_not_string(data: dict[str, object]) -> None:
    """Missing and non-string fields raise a stable TypeError."""
    with pytest.raises(TypeError, match="email must be a string"):
        _require_str(data, "email")


def test_managed_user_and_account_state_user_accept_protocol_compatible_users() -> None:
    """Protocol casts preserve access to required user attributes."""
    user = ExampleUser(id=uuid4())

    assert _managed_user(user).hashed_password == user.hashed_password
    assert _account_state_user(user).is_active is user.is_active
