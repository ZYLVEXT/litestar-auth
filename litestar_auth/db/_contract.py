"""SQLAlchemy model contract validation helpers."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, cast


@dataclass(frozen=True, slots=True)
class _UserModelContract:
    """Minimal declarative contract used to validate OAuth/user model alignment."""

    model_name: str | None
    table_name: str | None
    registry: object | None


def _describe_user_model_contract(user_model: type[Any]) -> _UserModelContract:
    """Return the user-model identity details that OAuth models point back to."""
    return _UserModelContract(
        model_name=cast("str | None", getattr(user_model, "__name__", None)),
        table_name=cast("str | None", getattr(user_model, "__tablename__", None)),
        registry=getattr(user_model, "registry", None),
    )


def _describe_oauth_user_contract(oauth_model: type[Any]) -> _UserModelContract | None:
    """Return the declared user-side contract for an OAuth model when available."""
    auth_user_model = getattr(oauth_model, "auth_user_model", None)
    auth_user_table = getattr(oauth_model, "auth_user_table", None)
    if not isinstance(auth_user_model, str) and not isinstance(auth_user_table, str):
        return None
    return _UserModelContract(
        model_name=auth_user_model if isinstance(auth_user_model, str) else None,
        table_name=auth_user_table if isinstance(auth_user_table, str) else None,
        registry=getattr(oauth_model, "registry", None),
    )


def _validate_oauth_account_model_contract(
    user_model: type[Any],
    oauth_model: type[Any],
) -> None:
    """Reject OAuth models that point at a different user class, table, or registry.

    The supported paths are:
    - the bundled ``OAuthAccount`` with a same-registry ``User`` mapped to ``user``
    - a custom ``OAuthAccountMixin`` subclass whose hooks target ``user_model``

    Raises:
        TypeError: When ``oauth_model`` points at a different user class, table,
            or registry than ``user_model``.
    """
    expected_contract = _describe_oauth_user_contract(oauth_model)
    if expected_contract is None:
        return

    actual_contract = _describe_user_model_contract(user_model)
    mismatches: list[str] = []
    if expected_contract.model_name is not None and actual_contract.model_name != expected_contract.model_name:
        mismatches.append(
            "auth_user_model="
            f"{expected_contract.model_name!r} does not match user_model.__name__={actual_contract.model_name!r}",
        )
    if expected_contract.table_name is not None and actual_contract.table_name != expected_contract.table_name:
        mismatches.append(
            "auth_user_table="
            f"{expected_contract.table_name!r} does not match user_model.__tablename__={actual_contract.table_name!r}",
        )
    if (
        expected_contract.registry is not None
        and actual_contract.registry is not None
        and expected_contract.registry is not actual_contract.registry
    ):
        mismatches.append("oauth_account_model and user_model use different declarative registries")

    if mismatches:
        msg = (
            "oauth_account_model does not match user_model: "
            + "; ".join(mismatches)
            + ". Use a matching OAuthAccountMixin subclass for custom users, or reuse "
            "litestar_auth.models.oauth.OAuthAccount only with a same-registry User mapped to the 'user' table."
        )
        raise TypeError(msg)
