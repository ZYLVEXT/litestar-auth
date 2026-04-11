"""Internal user-lifecycle service for ``BaseUserManager``."""
# ruff: noqa: ANN401, DOC201, DOC501, SLF001

from __future__ import annotations

from typing import TYPE_CHECKING, Any, Literal, Protocol, cast, runtime_checkable

from litestar_auth._manager._coercions import _as_dict, _managed_user, _require_str
from litestar_auth._manager._protocols import PasswordManagedUserManagerProtocol
from litestar_auth._manager.user_policy import UserPolicy
from litestar_auth.authentication.strategy.base import TokenInvalidationCapable
from litestar_auth.exceptions import UserAlreadyExistsError, UserNotExistsError

if TYPE_CHECKING:
    from collections.abc import Mapping

    import msgspec


class _UserLifecycleManagerProtocol[UP, ID](PasswordManagedUserManagerProtocol[UP], Protocol):
    """Manager surface required by the user-lifecycle service."""

    password_validator: Any
    reset_verification_on_email_change: bool
    backends: tuple[object, ...] | list[object]

    @staticmethod
    def _normalize_username_lookup(username: str) -> str: ...  # pragma: no cover

    def write_verify_token(self, user: UP) -> str: ...  # pragma: no cover

    async def on_after_register(self, user: UP, token: str) -> None: ...  # pragma: no cover

    async def on_after_request_verify_token(self, user: UP, token: str) -> None: ...  # pragma: no cover

    async def on_after_update(self, user: UP, update_dict: dict[str, Any]) -> None: ...  # pragma: no cover

    async def on_before_delete(self, user: UP) -> None: ...  # pragma: no cover

    async def on_after_delete(self, user: UP) -> None: ...  # pragma: no cover


@runtime_checkable
class _StrategyBackendProtocol[UP](Protocol):
    """Backend surface required for token invalidation dispatch."""

    strategy: object


SAFE_FIELDS = frozenset({"email", "password"})
PRIVILEGED_FIELDS = frozenset({"is_superuser", "is_active", "is_verified", "roles"})


class UserLifecycleService[UP, ID]:
    """Handle persistence-oriented user lifecycle operations."""

    def __init__(
        self,
        manager: _UserLifecycleManagerProtocol[UP, ID],
        *,
        policy: UserPolicy | None = None,
    ) -> None:
        """Bind the service to its facade manager.

        Args:
            manager: The owning manager facade.
            policy: Account-policy object; when ``None`` the service falls back to
                calling private methods on the manager for backward compatibility.
        """
        self._manager = manager
        self._policy = policy

    async def get(self, user_id: ID) -> UP | None:
        """Return a user by identifier."""
        return await self._manager.user_db.get(user_id)

    async def create(
        self,
        user_create: msgspec.Struct | Mapping[str, Any],
        *,
        safe: bool = True,
        allow_privileged: bool = False,
    ) -> UP:
        """Create a user via the manager facade contract."""
        user_dict = _as_dict(user_create)
        if safe:
            user_dict = {field_name: value for field_name, value in user_dict.items() if field_name in SAFE_FIELDS}
        if not allow_privileged:
            user_dict = {
                field_name: value for field_name, value in user_dict.items() if field_name not in PRIVILEGED_FIELDS
            }

        email = self._normalize_email(_require_str(user_dict, "email"))
        password = _require_str(user_dict, "password")
        self._validate_password(password)
        hashed_password = self._hash_password(password)
        existing_user = await self._manager.user_db.get_by_email(email)
        if existing_user is not None:
            raise UserAlreadyExistsError

        create_dict = {
            **user_dict,
            "email": email,
            "hashed_password": hashed_password,
        }
        create_dict.pop("password", None)
        self._normalize_roles_payload(create_dict)
        user = await self._manager.user_db.create(create_dict)
        token = self._manager.write_verify_token(user)
        await self._manager.on_after_register(user, token)
        return user

    async def list_users(self, *, offset: int, limit: int) -> tuple[list[UP], int]:
        """Return paginated users and their total count."""
        return await self._manager.user_db.list_users(offset=offset, limit=limit)

    async def authenticate(
        self,
        identifier: str,
        password: str,
        *,
        login_identifier: Literal["email", "username"],
        dummy_hash: str,
        logger: Any,
    ) -> UP | None:
        """Authenticate against the configured user database."""
        if login_identifier == "email":
            lookup = self._normalize_email(identifier)
            user = await self._manager.user_db.get_by_field("email", lookup)
        else:
            lookup = self._normalize_username_lookup(identifier)
            user = None if not lookup else await self._manager.user_db.get_by_field("username", lookup)
        hashed_password = _managed_user(user).hashed_password if user is not None else dummy_hash
        verified, new_hash = self._verify_and_update_password(password, hashed_password)
        if not verified or user is None:
            return None

        if new_hash is not None:
            try:
                user = await self._manager.user_db.update(user, {"hashed_password": new_hash})
            except Exception as exc:
                logger.warning(
                    "Password hash upgrade skipped (login succeeded)",
                    extra={"event": "password_upgrade_skipped", "user_id": str(user.id)},
                    exc_info=exc,
                )
        return user

    @staticmethod
    def require_account_state(user: UP, *, require_verified: bool = False) -> None:
        """Validate active and optionally verified account state."""
        UserPolicy.require_account_state(user, require_verified=require_verified)

    async def update(self, user_update: msgspec.Struct | Mapping[str, Any], user: UP) -> UP:
        """Update mutable user fields while preserving facade semantics."""
        update_dict = self._non_null_update_dict(user_update)
        if not update_dict:
            return user

        self._normalize_roles_payload(update_dict)
        new_email = await self._normalize_and_validate_email_change(update_dict=update_dict, user=user)
        email_changed = new_email is not None and new_email != _managed_user(user).email
        if email_changed and self._manager.reset_verification_on_email_change:
            update_dict["is_verified"] = False

        password_changed = self._apply_password_update(update_dict)

        updated_user = await self._manager.user_db.update(user, update_dict)
        await self._run_post_update_side_effects(
            updated_user=updated_user,
            email_changed=email_changed,
            password_changed=password_changed,
        )
        await self._manager.on_after_update(updated_user, update_dict)
        return updated_user

    @staticmethod
    def _non_null_update_dict(user_update: msgspec.Struct | Mapping[str, Any]) -> dict[str, Any]:
        """Build update payload from non-null incoming fields."""
        return {field_name: value for field_name, value in _as_dict(user_update).items() if value is not None}

    async def _normalize_and_validate_email_change(
        self,
        *,
        update_dict: dict[str, Any],
        user: UP,
    ) -> str | None:
        """Normalize and uniqueness-check email updates."""
        if "email" not in update_dict:
            return None

        new_email = self._normalize_email(_require_str(update_dict, "email"))
        update_dict["email"] = new_email
        existing_user = await self._manager.user_db.get_by_email(new_email)
        if existing_user is not None and _managed_user(existing_user).id != _managed_user(user).id:
            raise UserAlreadyExistsError
        return new_email

    def _apply_password_update(self, update_dict: dict[str, Any]) -> bool:
        """Hash and map password updates into persistence payload."""
        if "password" not in update_dict:
            return False

        password = _require_str(update_dict, "password")
        self._validate_password(password)
        update_dict["hashed_password"] = self._hash_password(password)
        update_dict.pop("password", None)
        return True

    def _normalize_roles_payload(self, update_dict: dict[str, Any]) -> None:
        """Normalize roles when a payload includes explicit role membership."""
        if "roles" not in update_dict:
            return

        update_dict["roles"] = self._normalize_roles(update_dict["roles"])

    async def _run_post_update_side_effects(
        self,
        *,
        updated_user: UP,
        email_changed: bool,
        password_changed: bool,
    ) -> None:
        """Invalidate tokens and issue re-verification token where required."""
        if email_changed or password_changed:
            await self.invalidate_all_tokens(updated_user)
        if email_changed and self._manager.reset_verification_on_email_change:
            token = self._manager.write_verify_token(updated_user)
            await self._manager.on_after_request_verify_token(updated_user, token)

    async def delete(self, user_id: ID) -> None:
        """Delete a user and execute lifecycle hooks."""
        user = await self._manager.user_db.get(user_id)
        if user is None:
            raise UserNotExistsError

        await self._manager.on_before_delete(user)
        await self._manager.user_db.delete(user_id)
        await self._manager.on_after_delete(user)

    def _normalize_email(self, email: str) -> str:
        if self._policy is not None:
            return self._policy.normalize_email(email)
        return self._manager._normalize_email(email)

    def _normalize_username_lookup(self, username: str) -> str:
        if self._policy is not None:
            return self._policy.normalize_username_lookup(username)
        return self._manager._normalize_username_lookup(username)

    def _normalize_roles(self, roles: object) -> list[str]:
        if self._policy is not None:
            return self._policy.normalize_roles(roles)
        return UserPolicy.normalize_roles(roles)

    def _validate_password(self, password: str) -> None:
        if self._policy is not None:
            self._policy.validate_password(password)
        else:
            self._manager._validate_password(password)

    def _hash_password(self, password: str) -> str:
        if self._policy is not None:
            return self._policy.password_helper.hash(password)
        return self._manager.password_helper.hash(password)

    def _verify_and_update_password(self, password: str, hashed_password: str) -> tuple[bool, str | None]:
        if self._policy is not None:
            return self._policy.password_helper.verify_and_update(password, hashed_password)
        return self._manager.password_helper.verify_and_update(password, hashed_password)

    async def invalidate_all_tokens(self, user: UP) -> None:
        """Invalidate backend-managed tokens when the strategy supports it."""
        for backend in self._manager.backends:
            if not isinstance(backend, _StrategyBackendProtocol):
                continue
            if isinstance(backend.strategy, TokenInvalidationCapable):
                strategy = cast("TokenInvalidationCapable[Any]", backend.strategy)
                await strategy.invalidate_all_tokens(user)
