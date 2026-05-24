"""Shared validation predicates for plugin configuration checks."""

from __future__ import annotations

from typing import cast

from sqlalchemy import inspect as sa_inspect


def user_model_defines_field(model_cls: object, field_name: str) -> bool:
    """Return whether ``user_model`` exposes ``field_name`` as a mapped or plain attribute."""
    mapper = sa_inspect(model_cls, raiseerr=False)
    if mapper is not None and hasattr(mapper, "has_property") and mapper.has_property(field_name):
        return True
    return hasattr(model_cls, field_name)


def schema_declares_field(schema: type[object], field_name: str) -> bool:
    """Return whether a msgspec schema declares ``field_name`` on its public contract."""
    return field_name in cast("tuple[str, ...]", getattr(schema, "__struct_fields__", ()))
