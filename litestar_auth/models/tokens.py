"""Canonical token-model registration helpers exposed from the models boundary."""

from __future__ import annotations

import importlib

from litestar_auth.authentication.strategy.db_models import AccessToken, RefreshToken  # noqa: TC001


def import_token_orm_models() -> tuple[type[AccessToken], type[RefreshToken]]:
    """Return the bundled token ORM models for explicit mapper registration.

    This is the canonical public bootstrap helper for the library token tables. It keeps
    token-model discovery under ``litestar_auth.models`` without importing the reference ``User``
    mapper.
    """
    db_models_module = importlib.import_module("litestar_auth.authentication.strategy.db_models")

    return db_models_module.import_token_orm_models()
