"""Repository factory helpers for database token strategies."""

from __future__ import annotations

from functools import cache
from typing import Any

from advanced_alchemy.repository import SQLAlchemyAsyncRepository
from sqlalchemy.ext.asyncio import AsyncSession, async_scoped_session

type AsyncSessionT = AsyncSession | async_scoped_session[AsyncSession]
type TokenRepositoryType = type[SQLAlchemyAsyncRepository[Any]]


@cache
def build_token_repository(token_model: type[Any]) -> TokenRepositoryType:
    """Create a repository type bound to the provided token model.

    Returns:
        Cached Advanced Alchemy async repository subclass for ``token_model``.
    """
    return type(
        f"{token_model.__name__}Repository",
        (SQLAlchemyAsyncRepository,),
        {"model_type": token_model, "id_attribute": "token"},
    )
