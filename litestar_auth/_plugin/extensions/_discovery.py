"""Entry-point discovery for opt-in external auth extensions."""

from __future__ import annotations

import logging
from importlib import metadata
from typing import TYPE_CHECKING, TypeGuard

from litestar_auth._plugin.extensions._contracts import EXTENSION_ENTRY_POINT_GROUP
from litestar_auth.exceptions import ConfigurationError

if TYPE_CHECKING:
    from collections.abc import Iterable
    from importlib.metadata import EntryPoint

    from litestar_auth._plugin.extensions._contracts import AuthExtension

logger = logging.getLogger(__name__)


def _iter_extension_entry_points() -> Iterable[EntryPoint]:
    return metadata.entry_points().select(group=EXTENSION_ENTRY_POINT_GROUP)


def _sort_entry_point(entry_point: EntryPoint) -> tuple[str, str]:
    return (entry_point.name, entry_point.value)


def _entry_point_label(entry_point: EntryPoint) -> str:
    return f"{entry_point.group}:{entry_point.name}={entry_point.value}"


def _is_auth_extension(candidate: object) -> TypeGuard[AuthExtension]:
    return (
        isinstance(getattr(candidate, "name", None), str)
        and callable(getattr(candidate, "validate", None))
        and callable(getattr(candidate, "register", None))
    )


def _instantiate_entry_point(entry_point: EntryPoint) -> object:
    try:
        loaded = entry_point.load()
    except Exception as exc:
        msg = f"Failed to load auth extension entry point {_entry_point_label(entry_point)!r}."
        raise ConfigurationError(msg) from exc

    if _is_auth_extension(loaded) and not isinstance(loaded, type):
        return loaded
    if not callable(loaded):
        msg = f"Auth extension entry point {_entry_point_label(entry_point)!r} did not load a valid AuthExtension."
        raise ConfigurationError(msg)

    try:
        return loaded()
    except Exception as exc:
        msg = f"Failed to instantiate auth extension entry point {_entry_point_label(entry_point)!r}."
        raise ConfigurationError(msg) from exc


def discover_extensions() -> tuple[AuthExtension, ...]:
    """Load external auth extensions registered under the canonical entry-point group.

    Returns:
        Discovered extension instances in deterministic entry-point order.

    Raises:
        ConfigurationError: If an entry point cannot load, cannot instantiate, or does not create an auth extension.
    """
    discovered: list[AuthExtension] = []
    for entry_point in sorted(_iter_extension_entry_points(), key=_sort_entry_point):
        extension = _instantiate_entry_point(entry_point)
        if not _is_auth_extension(extension):
            msg = (
                f"Auth extension entry point {_entry_point_label(entry_point)!r} did not create a valid AuthExtension."
            )
            raise ConfigurationError(msg)
        logger.info("Loaded auth extension entry point %s.", _entry_point_label(entry_point))
        discovered.append(extension)
    return tuple(discovered)


__all__ = ("EXTENSION_ENTRY_POINT_GROUP", "discover_extensions")
