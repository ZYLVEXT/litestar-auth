"""Default lifecycle hooks for ``BaseUserManager``."""

from __future__ import annotations

from typing import Any


class UserManagerHooks[UP]:
    """Default lifecycle-hook no-ops inherited by ``BaseUserManager``."""

    async def on_after_register(self, user: UP, token: str) -> None:
        """Hook invoked after a new user is created."""
        del self
        del user
        del token

    async def on_after_register_duplicate(self, user: UP) -> None:
        """Hook invoked after a duplicate registration attempt is detected.

        SECURITY: This hook receives the existing account so your application can
        enqueue an out-of-band notification to the real owner. Keep external I/O
        off the request path (e.g. use a queue or background task). Blocking here
        can reintroduce a timing oracle even though the HTTP response shape stays
        enumeration-resistant.
        """
        del self
        del user

    async def on_after_login(self, user: UP) -> None:
        """Hook invoked after a user authenticates successfully."""
        del self
        del user

    async def on_after_verify(self, user: UP) -> None:
        """Hook invoked after a user verifies their email."""
        del self
        del user

    async def on_after_request_verify_token(self, user: UP | None, token: str | None) -> None:
        """Hook invoked after a verify-token request is processed.

        SECURITY: When ``user`` is ``None``, the email either did not match any
        account or already belongs to a verified user. To prevent user
        enumeration via timing, your implementation MUST perform equivalent I/O
        in both cases (e.g. always enqueue a background task, whether or not an
        email will actually be sent). Do NOT conditionally skip work based on
        whether ``user`` is ``None``.
        """
        del self
        del user
        del token

    async def on_after_forgot_password(self, user: UP | None, token: str | None) -> None:
        """Hook invoked after a forgot-password request is processed.

        SECURITY: When ``user`` is ``None``, the email did not match any account.
        To prevent user enumeration via timing, your implementation MUST perform
        equivalent I/O in both cases (e.g., always enqueue a background task,
        whether or not an email will actually be sent). Do NOT conditionally
        skip work based on whether ``user`` is ``None``.
        """
        del self
        del user
        del token

    async def on_after_reset_password(self, user: UP) -> None:
        """Hook invoked after a password reset completes."""
        del self
        del user

    async def on_after_update(self, user: UP, update_dict: dict[str, Any]) -> None:
        """Hook invoked after a user is updated successfully."""
        del self
        del user
        del update_dict

    async def on_before_delete(self, user: UP) -> None:
        """Hook invoked before a user is deleted. Raise to cancel deletion."""
        del self
        del user

    async def on_after_delete(self, user: UP) -> None:
        """Hook invoked after a user is deleted permanently."""
        del self
        del user
