"""Repository factory helpers for the SQLAlchemy user database adapter."""

from __future__ import annotations

from functools import lru_cache
from typing import Any, Protocol, cast
from uuid import UUID

from advanced_alchemy.base import ModelProtocol
from advanced_alchemy.repository import SQLAlchemyAsyncRepository
from sqlalchemy import inspect
from sqlalchemy.exc import NoInspectionAvailable

from litestar_auth.types import UserProtocol


class SQLAlchemyUserModelProtocol(ModelProtocol, UserProtocol[UUID], Protocol):
    """Protocol for SQLAlchemy user models handled by this adapter."""


type UserModelT[UP: SQLAlchemyUserModelProtocol] = type[UP]


@lru_cache(maxsize=16)
def _build_user_repository[UP: SQLAlchemyUserModelProtocol](
    user_model: UserModelT[UP],
) -> type[SQLAlchemyAsyncRepository[UP]]:
    """Create a repository type bound to the provided SQLAlchemy user model.

    Cached by ``user_model`` identity so repeated adapter construction does not
    allocate new dynamic repository classes.

    Returns:
        Repository class configured for ``user_model``.
    """
    return cast(
        "type[SQLAlchemyAsyncRepository[UP]]",
        type(
            f"{user_model.__name__}Repository",
            (SQLAlchemyAsyncRepository,),
            {"model_type": user_model},
        ),
    )


@lru_cache(maxsize=16)
def _build_oauth_repository(oauth_model: type[Any]) -> type[SQLAlchemyAsyncRepository[Any]]:
    """Create a repository type bound to the provided OAuth account model.

    Returns:
        A cached Advanced Alchemy async repository subclass for ``oauth_model``.
    """
    return cast(
        "type[SQLAlchemyAsyncRepository[Any]]",
        type(
            f"{oauth_model.__name__}OAuthRepository",
            (SQLAlchemyAsyncRepository,),
            {"model_type": oauth_model},
        ),
    )


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
    return (cast("Any", user_model).role_assignments,)
