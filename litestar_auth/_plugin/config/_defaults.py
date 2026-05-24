"""Resolved default snapshots for plugin configuration."""

from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING, Any

from litestar_auth._plugin import features as _features
from litestar_auth.config import UNSET, UnsetType
from litestar_auth.types import UserProtocol

if TYPE_CHECKING:
    from collections.abc import Callable

    from litestar_auth._plugin.config._core import LitestarAuthConfig
    from litestar_auth._plugin.config._protocols import UserDatabaseFactory


@dataclass(frozen=True, slots=True)
class ResolvedAuthConfigDefaults[UP: UserProtocol[Any], ID]:
    """Resolved defaults for one ``LitestarAuthConfig`` instance."""

    user_db_factory: UserDatabaseFactory[UP, ID] | UnsetType
    id_parser: Callable[[str], ID] | UnsetType
    features: _features.ResolvedFeatureDefaults


def _resolve_config_defaults[UP: UserProtocol[Any], ID](
    config: LitestarAuthConfig[UP, ID],
) -> ResolvedAuthConfigDefaults[UP, ID]:
    """Resolve top-level plugin defaults in one place.

    Returns:
        Resolved auth config defaults for startup and request-time helpers.
    """
    user_db_factory = UNSET if config.user_db_factory is None else config.user_db_factory
    id_parser = UNSET
    if config.id_parser is not None:
        id_parser = config.id_parser
    elif config.user_manager_security is not None and config.user_manager_security.id_parser is not None:
        id_parser = config.user_manager_security.id_parser
    return ResolvedAuthConfigDefaults(
        user_db_factory=user_db_factory,
        id_parser=id_parser,
        features=_features.resolve_feature_defaults(config),
    )
