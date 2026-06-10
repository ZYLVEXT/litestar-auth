"""Token-model registration helpers exposed from the models boundary."""

from __future__ import annotations

import importlib

from litestar_auth.authentication.strategy.db_models import (  # noqa: TC001
    AccessToken,
    RefreshToken,
    RefreshTokenConsumedDigest,
)


def import_token_orm_models() -> tuple[type[AccessToken], type[RefreshToken], type[RefreshTokenConsumedDigest]]:
    """Return all bundled token ORM models for explicit and plugin-owned bootstrap.

    This remains the public helper for metadata bootstrap and Alembic-style
    autogenerate flows. ``LitestarAuth.on_app_init()`` also calls it lazily when bundled
    DB-token models are active, so plugin-managed runtime no longer depends on a separate
    app-level import side effect. The helper keeps token-model discovery under
    ``litestar_auth.models`` without importing the reference ``User`` mapper.
    """
    db_models_module = importlib.import_module("litestar_auth.authentication.strategy.db_models")

    return db_models_module.import_token_orm_models()
