"""SQLAlchemy role model family resolution for plugin role administration."""

from __future__ import annotations

from dataclasses import dataclass
from functools import cache
from typing import Any, cast

from sqlalchemy import inspect
from sqlalchemy.exc import NoInspectionAvailable

from litestar_auth.exceptions import ConfigurationError
from litestar_auth.types import UserProtocol

_ROLE_ASSIGNMENTS_RELATIONSHIP_NAME = "role_assignments"
_ROLE_RELATIONSHIP_NAME = "role"


def _model_name(model: object) -> str:
    """Return a stable display name for a configured model class."""
    return cast("str", getattr(model, "__name__", repr(model)))


def _role_contract_error(
    user_model: object,
    detail: str,
) -> str:
    """Build one fail-closed error message for incompatible role contracts.

    Returns:
        The error message describing the incompatible role contract.
    """
    return (
        "Role admin requires LitestarAuthConfig.user_model "
        f"{_model_name(user_model)!r} to compose UserRoleRelationshipMixin or an equivalent "
        f"relational role contract. {detail}"
    )


@dataclass(frozen=True, slots=True)
class RoleModelFamily[UP: UserProtocol[Any]]:
    """Resolved SQLAlchemy model family behind the flat user-role contract."""

    user_model: type[UP]
    role_model: type[Any]
    user_role_model: type[Any]


def _inspect_user_role_relationships(user_model: object) -> Any:  # noqa: ANN401
    """Return SQLAlchemy relationships for ``user_model`` or raise a contract error.

    Returns:
        SQLAlchemy relationship collection for the mapped user model.

    Raises:
        ConfigurationError: If ``user_model`` does not satisfy the role-admin contract.
    """
    if not hasattr(user_model, "roles"):
        msg = _role_contract_error(
            user_model,
            "Expected a normalized flat 'roles' attribute on the user model.",
        )
        raise ConfigurationError(msg)

    try:
        user_relationships = cast("Any", inspect(user_model)).relationships
    except NoInspectionAvailable as exc:
        msg = _role_contract_error(
            user_model,
            "Expected a SQLAlchemy mapped class, but mapper inspection is unavailable.",
        )
        raise ConfigurationError(msg) from exc

    if _ROLE_ASSIGNMENTS_RELATIONSHIP_NAME not in user_relationships:
        msg = _role_contract_error(
            user_model,
            "Expected a mapped 'role_assignments' relationship on the user model.",
        )
        raise ConfigurationError(msg)
    return user_relationships


def _resolve_user_role_model(user_model: object, user_relationships: Any) -> type[Any]:  # noqa: ANN401
    """Return the mapped role-assignment model from inspected user relationships.

    Returns:
        SQLAlchemy model class for user-role assignment rows.

    Raises:
        ConfigurationError: If the assignment model does not satisfy the role-admin contract.
    """
    user_role_model = cast(
        "type[Any]",
        user_relationships[_ROLE_ASSIGNMENTS_RELATIONSHIP_NAME].mapper.class_,
    )
    if not hasattr(user_role_model, "role_name"):
        msg = _role_contract_error(
            user_model,
            "Expected role-assignment rows with a normalized 'role_name' attribute.",
        )
        raise ConfigurationError(msg)
    return user_role_model


def _resolve_role_model(user_model: object, user_role_model: object) -> type[Any]:
    """Return the mapped role model from the role-assignment model.

    Returns:
        SQLAlchemy model class for catalog role rows.

    Raises:
        ConfigurationError: If the role model does not satisfy the role-admin contract.
    """
    user_role_relationships = cast("Any", inspect(user_role_model)).relationships
    if _ROLE_RELATIONSHIP_NAME not in user_role_relationships:
        msg = _role_contract_error(
            user_model,
            "Expected role-assignment rows with a mapped 'role' relationship.",
        )
        raise ConfigurationError(msg)

    role_model = cast(
        "type[Any]",
        user_role_relationships[_ROLE_RELATIONSHIP_NAME].mapper.class_,
    )
    if not hasattr(role_model, "name"):
        msg = _role_contract_error(
            user_model,
            "Expected related role rows with a normalized 'name' attribute.",
        )
        raise ConfigurationError(msg)
    return role_model


@cache
def resolve_role_model_family[UP: UserProtocol[Any]](
    user_model: type[UP],
) -> RoleModelFamily[UP]:
    """Resolve the active relational role model family from ``user_model``.

    Returns:
        The resolved SQLAlchemy user, role, and association models.

    Contract failures are reported as ``ConfigurationError`` by the validation helpers.
    """
    user_relationships = _inspect_user_role_relationships(user_model)
    user_role_model = _resolve_user_role_model(user_model, user_relationships)
    role_model = _resolve_role_model(user_model, user_role_model)
    return RoleModelFamily(
        user_model=user_model,
        role_model=role_model,
        user_role_model=user_role_model,
    )
