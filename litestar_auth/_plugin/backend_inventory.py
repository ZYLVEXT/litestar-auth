"""Startup backend inventory helpers for plugin assembly and request binding."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Any, cast

from litestar_auth.types import UserProtocol

if TYPE_CHECKING:
    from collections.abc import Callable, Sequence

    from sqlalchemy.ext.asyncio import AsyncSession

    from litestar_auth._plugin.config import LitestarAuthConfig
    from litestar_auth.authentication.backend import AuthenticationBackend
    from litestar_auth.types import StrategyProtocol, TransportProtocol


@dataclass(frozen=True, slots=True, eq=False)
class StartupBackendTemplate[UP: UserProtocol[Any], ID]:
    """Startup-only backend template used for plugin assembly and validation."""

    name: str
    transport: TransportProtocol
    strategy: StrategyProtocol[UP, ID]
    _runtime_backend_factory: Callable[[AsyncSession], AuthenticationBackend[UP, ID]] = field(
        repr=False,
    )

    def __eq__(self, other: object) -> bool:
        if self is other:
            return True
        if not isinstance(other, type(self)):
            return NotImplemented
        return self.name == other.name and self.transport is other.transport and self.strategy is other.strategy

    def __hash__(self) -> int:
        return hash((self.name, id(self.transport), id(self.strategy)))

    @classmethod
    def from_runtime_backend(
        cls,
        backend: AuthenticationBackend[UP, ID],
    ) -> StartupBackendTemplate[UP, ID]:
        """Wrap a runtime backend in the startup-only template type.

        Returns:
            Startup-only template carrying the runtime backend's public surface and
            session-binding factory.
        """
        return cls(
            name=backend.name,
            transport=backend.transport,
            strategy=backend.strategy,
            _runtime_backend_factory=backend.with_session,
        )

    def bind_runtime_backend(self, session: AsyncSession) -> AuthenticationBackend[UP, ID]:
        """Materialize the request-scoped runtime backend for ``session``.

        Returns:
            Runtime authentication backend rebound to ``session``.
        """
        return self._runtime_backend_factory(session)


@dataclass(frozen=True, slots=True)
class StartupBackendInventory[UP: UserProtocol[Any], ID]:
    """Central startup inventory reused by plugin assembly and request binding."""

    startup_backend_templates: tuple[StartupBackendTemplate[UP, ID], ...]

    def startup_backends(self) -> tuple[StartupBackendTemplate[UP, ID], ...]:
        """Return the startup-only backend templates in configured order."""
        return self.startup_backend_templates

    def bind_request_backends(self, session: AsyncSession) -> tuple[AuthenticationBackend[UP, ID], ...]:
        """Return request-scoped runtime backends aligned with the startup inventory."""
        return tuple(backend.bind_runtime_backend(session) for backend in self.startup_backend_templates)

    def primary(self) -> tuple[int, StartupBackendTemplate[UP, ID]]:
        """Return the primary startup backend and its startup-order index."""
        return 0, self.startup_backend_templates[0]

    def resolve_named(self, backend_name: str) -> tuple[int, StartupBackendTemplate[UP, ID]]:
        """Return the startup backend matching ``backend_name`` plus its index.

        Raises:
            ValueError: If ``backend_name`` is not part of the startup inventory.
        """
        for index, backend in enumerate(self.startup_backend_templates):
            if backend.name == backend_name:
                return index, backend

        msg = f"Unknown TOTP backend: {backend_name}"
        raise ValueError(msg)

    def resolve_request_backend(
        self,
        request_backends: object,
        *,
        backend_index: int,
    ) -> AuthenticationBackend[UP, ID]:
        """Return the request-scoped backend matching ``backend_index`` from startup.

        Raises:
            RuntimeError: If the request-time backend inventory diverges from plugin startup.
        """
        expected_backend = self.startup_backend_templates[backend_index]
        backends = cast("Sequence[AuthenticationBackend[UP, ID]]", request_backends)
        if len(backends) <= backend_index:
            msg = (
                "litestar_auth_backends did not provide the backend sequence expected by the plugin. "
                f"Missing backend index {backend_index} for {expected_backend.name!r}."
            )
            raise RuntimeError(msg)

        backend = backends[backend_index]
        if backend.name != expected_backend.name:
            msg = (
                "litestar_auth_backends no longer matches the plugin startup backend order. "
                f"Expected backend {expected_backend.name!r} at index {backend_index}, got {backend.name!r}."
            )
            raise RuntimeError(msg)
        return backend

    def resolve_totp(self, *, backend_name: str | None) -> tuple[int, StartupBackendTemplate[UP, ID]]:
        """Return the TOTP startup backend, defaulting to the primary backend."""
        if backend_name is None:
            return self.primary()
        return self.resolve_named(backend_name)


def resolve_backend_inventory[UP: UserProtocol[Any], ID](
    config: LitestarAuthConfig[UP, ID],
) -> StartupBackendInventory[UP, ID]:
    """Return the centralized startup inventory for plugin assembly and request binding.

    Returns:
        Startup inventory for the current config, including stable slot metadata used to
        resolve request-scoped backends.

    Raises:
        ValueError: If both ``database_token_auth`` and manual ``backends`` are configured.
    """
    if config.database_token_auth is not None and config.backends:
        msg = "Configure authentication backends via database_token_auth=... or backends=..., not both."
        raise ValueError(msg)
    startup_backends: tuple[StartupBackendTemplate[UP, ID], ...]
    if config.database_token_auth is not None:
        from litestar_auth._plugin import database_token as _database_token_module  # noqa: PLC0415

        startup_backends = (
            _database_token_module._build_database_token_backend_template(  # noqa: SLF001
                config.database_token_auth,
                unsafe_testing=config.unsafe_testing,
            ),
        )
    else:
        startup_backends = tuple(StartupBackendTemplate.from_runtime_backend(backend) for backend in config.backends)
    return StartupBackendInventory(startup_backends)
