"""Repository factory helpers for the SQLAlchemy user database adapter."""

from __future__ import annotations

from functools import lru_cache
from typing import TYPE_CHECKING, Any, ClassVar, Protocol, cast
from uuid import UUID

from advanced_alchemy.base import ModelProtocol
from advanced_alchemy.repository import SQLAlchemyAsyncRepository
from sqlalchemy import inspect
from sqlalchemy.exc import NoInspectionAvailable

from litestar_auth.types import UserProtocol

if TYPE_CHECKING:
    from sqlalchemy.orm import InstrumentedAttribute


class SQLAlchemyUserModelProtocol(ModelProtocol, UserProtocol[UUID], Protocol):
    """Protocol for SQLAlchemy user models handled by this adapter."""


class _RoleAssignableUserModel(Protocol):
    """User model shape for optional role-assignment eager loading."""

    role_assignments: ClassVar[InstrumentedAttribute[list[Any]]]


type UserModelT[UP: SQLAlchemyUserModelProtocol] = type[UP]


@lru_cache(maxsize=16)
def _build_model_repository[ModelT: ModelProtocol](
    model: type[ModelT],
) -> type[SQLAlchemyAsyncRepository[ModelT]]:
    """Create a repository type bound to the provided SQLAlchemy model.

    Returns:
        Repository class configured for ``model``.
    """
    return cast(
        "type[SQLAlchemyAsyncRepository[ModelT]]",
        type(
            f"{model.__name__}Repository",
            (SQLAlchemyAsyncRepository,),
            {"model_type": model},
        ),
    )


def _build_user_repository[UP: SQLAlchemyUserModelProtocol](
    user_model: UserModelT[UP],
) -> type[SQLAlchemyAsyncRepository[UP]]:
    """Return the cached repository type bound to the configured user model."""
    return cast("type[SQLAlchemyAsyncRepository[UP]]", _build_model_repository(user_model))


def _build_oauth_repository(oauth_model: type[Any]) -> type[SQLAlchemyAsyncRepository[Any]]:
    """Return the cached repository type bound to the configured OAuth account model."""
    return _build_model_repository(oauth_model)


@lru_cache(maxsize=16)
def _build_user_load[UP: SQLAlchemyUserModelProtocol](
    user_model: UserModelT[UP],
) -> tuple[Any, ...]:
    """Return repository load options required by the configured user model."""
    try:
        relationships = inspect(user_model).relationships
    except NoInspectionAvailable:
        return ()
    if "role_assignments" not in relationships:
        return ()
    return (cast("type[_RoleAssignableUserModel]", user_model).role_assignments,)
