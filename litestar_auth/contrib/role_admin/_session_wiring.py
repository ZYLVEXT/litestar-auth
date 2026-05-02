"""Request-scoped session wiring for contrib role-administration helpers."""

from __future__ import annotations

from typing import TYPE_CHECKING, Any, cast

from litestar_auth._plugin.role_admin import RoleModelFamily, SQLAlchemyRoleAdmin
from litestar_auth.exceptions import ConfigurationError
from litestar_auth.types import UserProtocol

if TYPE_CHECKING:
    from sqlalchemy.ext.asyncio import AsyncSession


class _RequestSessionContextManager:
    """Async context manager that reuses the current request-scoped session."""

    def __init__(self, session: AsyncSession) -> None:
        """Store the existing request-scoped session."""
        self._session = session

    async def __aenter__(self) -> AsyncSession:
        """Return the shared request session."""
        return self._session

    async def __aexit__(
        self,
        exc_type: type[BaseException] | None,
        exc: BaseException | None,
        traceback: object,
    ) -> None:
        """Leave session lifecycle management to the surrounding request scope."""
        del exc_type, exc, traceback


class _RequestSessionMaker:
    """Session-maker adapter that exposes an existing request session as a ``session_maker()`` callable."""

    def __init__(self, session: AsyncSession) -> None:
        """Store the existing request-scoped session."""
        self._session = session

    def __call__(self) -> _RequestSessionContextManager:
        """Return an async context manager yielding the stored session."""
        return _RequestSessionContextManager(self._session)


class _UnusedRoleLifecycleUpdater:
    """Sentinel lifecycle updater for request-bound helpers that never force delete."""

    @staticmethod
    def build_manager(session: AsyncSession) -> object:
        """Fail closed if a code path unexpectedly requests lifecycle updates.

        Raises:
            AssertionError: Always, because the HTTP role-catalog surface does
                not support forced deletes.
        """
        del session
        msg = "HTTP role catalog handlers never build manager lifecycle updates without an explicit force operation."
        raise AssertionError(msg)


class _ProvidedUserManagerLifecycleUpdater:
    """Request-bound lifecycle updater that reuses an injected manager when present."""

    def __init__(self, user_manager: object | None) -> None:
        """Store the optional request-scoped user manager dependency."""
        self._user_manager = user_manager

    def build_manager(self, session: AsyncSession) -> object:
        """Return the injected manager or fail closed for assignment handlers.

        Raises:
            ConfigurationError: If no manager dependency was provided for an
                explicit-model request-bound controller.
        """
        del session
        if self._user_manager is not None:
            return self._user_manager

        msg = (
            "Role admin assignment handlers require a request-scoped litestar_auth_user_manager when "
            "create_role_admin_controller() is used without config."
        )
        raise ConfigurationError(msg)


def _build_request_bound_role_admin[UP: UserProtocol[Any]](
    *,
    model_family: RoleModelFamily[UP],
    session: AsyncSession,
    role_lifecycle_updater: object,
) -> SQLAlchemyRoleAdmin[UP]:
    """Return a helper that reuses the current request-scoped session."""
    return SQLAlchemyRoleAdmin(
        model_family=model_family,
        _session_maker=cast("Any", _RequestSessionMaker(session)),
        _role_lifecycle_updater=cast("Any", role_lifecycle_updater),
    )
