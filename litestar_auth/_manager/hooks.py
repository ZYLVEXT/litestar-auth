"""Default lifecycle hooks for ``BaseUserManager``."""

from __future__ import annotations

from collections.abc import Awaitable, Callable
from dataclasses import dataclass
from typing import Any, Literal, overload

type ManagerHookName = Literal[
    "after_register",
    "after_register_duplicate",
    "after_login",
    "after_verify",
    "after_request_verify_token",
    "after_forgot_password",
    "after_reset_password",
    "after_update",
    "before_delete",
    "after_delete",
    "after_api_key_created",
    "after_api_key_revoked",
    "after_api_key_used",
]


@dataclass(frozen=True, slots=True)
class ManagerHookEvent:
    """Lifecycle-hook event dispatched through ``ManagerHookBus``."""

    name: ManagerHookName
    args: tuple[object, ...]


type ManagerHookSubscriber = Callable[[ManagerHookEvent], Awaitable[None]]


class ManagerHookBus[UP]:
    """Dispatch manager lifecycle hooks and optional event subscribers."""

    def __init__(self, hooks: object) -> None:
        """Bind the hook target that receives the primary lifecycle callbacks."""
        self._hooks = hooks
        self._subscribers: list[ManagerHookSubscriber] = []

    def subscribe(self, subscriber: ManagerHookSubscriber) -> Callable[[], None]:
        """Register a lifecycle-event subscriber.

        Returns:
            Callback that unregisters the subscriber.
        """
        self._subscribers.append(subscriber)

        def unsubscribe() -> None:
            self._subscribers.remove(subscriber)

        return unsubscribe

    @overload
    async def fire(self, name: Literal["after_register"], user: UP, token: str) -> None: ...

    @overload
    async def fire(self, name: Literal["after_register_duplicate"], user: UP) -> None: ...

    @overload
    async def fire(self, name: Literal["after_login"], user: UP) -> None: ...

    @overload
    async def fire(self, name: Literal["after_verify"], user: UP) -> None: ...

    @overload
    async def fire(
        self,
        name: Literal["after_request_verify_token"],
        user: UP | None,
        token: str | None,
    ) -> None: ...

    @overload
    async def fire(
        self,
        name: Literal["after_forgot_password"],
        user: UP | None,
        token: str | None,
    ) -> None: ...

    @overload
    async def fire(self, name: Literal["after_reset_password"], user: UP) -> None: ...

    @overload
    async def fire(
        self,
        name: Literal["after_update"],
        user: UP,
        update_dict: dict[str, Any],
    ) -> None: ...

    @overload
    async def fire(self, name: Literal["before_delete"], user: UP) -> None: ...

    @overload
    async def fire(self, name: Literal["after_delete"], user: UP) -> None: ...

    @overload
    async def fire(
        self,
        name: Literal["after_api_key_created"],
        user: UP,
        api_key: object,
    ) -> None: ...

    @overload
    async def fire(
        self,
        name: Literal["after_api_key_revoked"],
        user: UP,
        api_key: object,
    ) -> None: ...

    @overload
    async def fire(self, name: Literal["after_api_key_used"], api_key: object) -> None: ...

    async def fire(self, name: ManagerHookName, *args: object) -> None:
        """Dispatch one lifecycle hook, then notify event subscribers."""
        hook = getattr(self._hooks, f"on_{name}")
        await hook(*args)
        event = ManagerHookEvent(name=name, args=args)
        for subscriber in tuple(self._subscribers):
            await subscriber(event)


class UserManagerHooks[UP]:
    """Default lifecycle-hook no-ops inherited by ``BaseUserManager``."""

    async def on_after_register(self, user: UP, token: str) -> None:
        """Hook invoked after a new user is created."""

    async def on_after_register_duplicate(self, user: UP) -> None:
        """Hook invoked after a duplicate registration attempt is detected.

        SECURITY: This hook receives the existing account so your application can
        enqueue an out-of-band notification to the real owner. Keep external I/O
        off the request path (e.g. use a queue or background task). Blocking here
        can reintroduce a timing oracle even though the HTTP response shape stays
        enumeration-resistant.
        """

    async def on_after_login(self, user: UP) -> None:
        """Hook invoked after a user authenticates successfully."""

    async def on_after_verify(self, user: UP) -> None:
        """Hook invoked after a user verifies their email."""

    async def on_after_request_verify_token(self, user: UP | None, token: str | None) -> None:
        """Hook invoked after a verify-token request is processed.

        SECURITY: When ``user`` is ``None``, the email either did not match any
        account or already belongs to a verified user. To prevent user
        enumeration via timing, your implementation MUST perform equivalent I/O
        in both cases (e.g. always enqueue a background task, whether or not an
        email will actually be sent). Do NOT conditionally skip work based on
        whether ``user`` is ``None``.
        """

    async def on_after_forgot_password(self, user: UP | None, token: str | None) -> None:
        """Hook invoked after a forgot-password request is processed.

        SECURITY: When ``user`` is ``None``, the email did not match any account.
        To prevent user enumeration via timing, your implementation MUST perform
        equivalent I/O in both cases (e.g., always enqueue a background task,
        whether or not an email will actually be sent). Do NOT conditionally
        skip work based on whether ``user`` is ``None``.
        """

    async def on_after_reset_password(self, user: UP) -> None:
        """Hook invoked after a password reset completes."""

    async def on_after_update(self, user: UP, update_dict: dict[str, Any]) -> None:
        """Hook invoked after a user is updated successfully."""

    async def on_before_delete(self, user: UP) -> None:
        """Hook invoked before a user is deleted. Raise to cancel deletion."""

    async def on_after_delete(self, user: UP) -> None:
        """Hook invoked after a user is deleted permanently."""

    async def on_after_api_key_created(self, user: UP, api_key: object) -> None:
        """Hook invoked after an API key is created."""

    async def on_after_api_key_revoked(self, user: UP, api_key: object) -> None:
        """Hook invoked after an API key is revoked."""

    async def on_after_api_key_used(self, api_key: object) -> None:
        """Hook invoked after an API-key last-used timestamp is persisted."""
