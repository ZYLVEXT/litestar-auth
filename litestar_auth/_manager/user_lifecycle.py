"""Internal user-lifecycle service for ``BaseUserManager``."""
# ruff: noqa: ANN401, DOC201, DOC501

from __future__ import annotations

from typing import TYPE_CHECKING, Any, Literal, Protocol, cast, runtime_checkable

from litestar_auth._concurrency import run_password_op_in_worker_thread as _run_password_op
from litestar_auth._manager._coercions import _as_dict, _managed_user, _require_str
from litestar_auth._manager._protocols import UserDatabaseManagerProtocol
from litestar_auth._manager.hooks import ManagerHookBus
from litestar_auth._manager.user_policy import PRIVILEGED_FIELDS as _PRIVILEGED_FIELDS
from litestar_auth._manager.user_policy import UserPolicy
from litestar_auth.authentication.strategy.base import TokenInvalidationCapable
from litestar_auth.exceptions import UserAlreadyExistsError, UserIdentifier, UserNotExistsError

if TYPE_CHECKING:
    from collections.abc import Mapping

    import msgspec

PRIVILEGED_FIELDS = _PRIVILEGED_FIELDS


class _UserLifecycleManagerProtocol[UP, ID](
    UserDatabaseManagerProtocol[UP],
    Protocol,
):
    """Manager surface required by the user-lifecycle service."""

    reset_verification_on_email_change: bool
    backends: tuple[object, ...] | list[object]

    def write_verify_token(self, user: UP) -> str:
        """Issue a verification token for the supplied user."""


@runtime_checkable
class _StrategyBackendProtocol[UP](Protocol):
    """Backend surface required for token invalidation dispatch."""

    strategy: object


@runtime_checkable
class _ApiKeyBulkDeleteStoreProtocol[ID](Protocol):
    """API-key store surface required for hard-delete cleanup."""

    async def delete_for_user(self, user_id: ID) -> int:
        """Delete API-key rows owned by ``user_id``."""


class UserLifecycleService[UP, ID]:
    """Handle persistence-oriented user lifecycle operations."""

    def __init__(
        self,
        manager: _UserLifecycleManagerProtocol[UP, ID],
        *,
        hook_bus: ManagerHookBus[UP] | None = None,
        policy: UserPolicy,
    ) -> None:
        """Bind the service to its facade manager.

        Args:
            manager: The owning manager facade.
            hook_bus: Dispatcher used for all lifecycle-hook callbacks.
            policy: Account-policy object providing email normalization,
                username lookup normalization, password validation, and password
                hashing. Required so every code path goes through the single
                policy boundary without any fallback into manager privates.
        """
        self._manager = manager
        self._hook_bus = hook_bus or ManagerHookBus(manager)
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
        user_dict = self._policy.field_policy.filter_create_payload(
            user_dict,
            safe=safe,
            allow_privileged=allow_privileged,
        )

        email = self._policy.normalize_email(_require_str(user_dict, "email"))
        password = _require_str(user_dict, "password")
        self._policy.validate_password(password)
        hashed_password = await _run_password_op(self._policy.password_helper.hash, password)
        existing_user = await self._manager.user_db.get_by_email(email)
        if existing_user is not None:
            await self._hook_bus.fire("after_register_duplicate", existing_user)
            raise UserAlreadyExistsError(
                identifier=UserIdentifier(identifier_type="email", identifier_value=email),
                message=UserAlreadyExistsError.default_message,
            )

        create_dict = {
            **user_dict,
            "email": email,
            "hashed_password": hashed_password,
        }
        create_dict.pop("password", None)
        self._normalize_roles_payload(create_dict)
        user = await self._manager.user_db.create(create_dict)
        token = self._manager.write_verify_token(user)
        await self._hook_bus.fire("after_register", user, token)
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
            lookup = self._policy.normalize_email(identifier)
            user = await self._manager.user_db.get_by_field("email", lookup)
        else:
            lookup = self._policy.normalize_username_lookup(identifier)
            user = None if not lookup else await self._manager.user_db.get_by_field("username", lookup)
        hashed_password = _managed_user(user).hashed_password if user is not None else dummy_hash
        verified, new_hash = await _run_password_op(
            self._policy.password_helper.verify_and_update,
            password,
            hashed_password,
        )
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

    async def update(
        self,
        user_update: msgspec.Struct | Mapping[str, Any],
        user: UP,
        *,
        allow_privileged: bool = False,
    ) -> UP:
        """Update mutable user fields while preserving facade semantics."""
        update_dict = self._non_null_update_dict(user_update)
        if not update_dict:
            return user
        self._policy.field_policy.validate_update_payload(update_dict, allow_privileged=allow_privileged)

        self._normalize_roles_payload(update_dict)
        new_email = await self._normalize_and_validate_email_change(update_dict=update_dict, user=user)
        email_changed = new_email is not None and new_email != _managed_user(user).email
        if email_changed and self._manager.reset_verification_on_email_change:
            update_dict["is_verified"] = False

        password_changed = await self._apply_password_update(update_dict)

        updated_user = await self._manager.user_db.update(user, update_dict)
        await self._run_post_update_side_effects(
            updated_user=updated_user,
            email_changed=email_changed,
            password_changed=password_changed,
            deactivated=update_dict.get("is_active") is False,
        )
        await self._hook_bus.fire("after_update", updated_user, update_dict)
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

        new_email = self._policy.normalize_email(_require_str(update_dict, "email"))
        update_dict["email"] = new_email
        existing_user = await self._manager.user_db.get_by_email(new_email)
        if existing_user is not None and _managed_user(existing_user).id != _managed_user(user).id:
            raise UserAlreadyExistsError(
                identifier=UserIdentifier(identifier_type="email", identifier_value=new_email),
                message=UserAlreadyExistsError.default_message,
            )
        return new_email

    async def _apply_password_update(self, update_dict: dict[str, Any]) -> bool:
        """Hash and map password updates into persistence payload."""
        if "password" not in update_dict:
            return False

        password = _require_str(update_dict, "password")
        self._policy.validate_password(password)
        update_dict["hashed_password"] = await _run_password_op(self._policy.password_helper.hash, password)
        update_dict.pop("password", None)
        return True

    def _normalize_roles_payload(self, update_dict: dict[str, Any]) -> None:
        """Normalize roles when a payload includes explicit role membership."""
        if "roles" not in update_dict:
            return

        update_dict["roles"] = self._policy.normalize_roles(update_dict["roles"])

    async def _run_post_update_side_effects(
        self,
        *,
        updated_user: UP,
        email_changed: bool,
        password_changed: bool,
        deactivated: bool,
    ) -> None:
        """Invalidate tokens and issue re-verification token where required."""
        if email_changed or password_changed or deactivated:
            await self.invalidate_all_tokens(updated_user)
        if deactivated:
            await self._delete_api_keys_for_user(_managed_user(updated_user).id)
        if email_changed and self._manager.reset_verification_on_email_change:
            token = self._manager.write_verify_token(updated_user)
            await self._hook_bus.fire("after_request_verify_token", updated_user, token)

    async def delete(self, user_id: ID) -> None:
        """Delete a user and execute lifecycle hooks."""
        user = await self._manager.user_db.get(user_id)
        if user is None:
            raise UserNotExistsError

        await self._hook_bus.fire("before_delete", user)
        await self.invalidate_all_tokens(user)
        await self._delete_api_keys_for_user(user_id)
        await self._manager.user_db.delete(user_id)
        await self._hook_bus.fire("after_delete", user)

    async def invalidate_all_tokens(self, user: UP) -> None:
        """Invalidate backend-managed tokens when the strategy supports it."""
        for backend in self._manager.backends:
            if not isinstance(backend, _StrategyBackendProtocol):
                continue
            if isinstance(backend.strategy, TokenInvalidationCapable):
                strategy = cast("TokenInvalidationCapable[Any]", backend.strategy)
                await strategy.invalidate_all_tokens(user)

    async def _delete_api_keys_for_user(self, user_id: ID) -> None:
        """Delete API keys when the manager has a bulk-delete-capable store."""
        api_key_store = getattr(self._manager, "api_key_store", None)
        if isinstance(api_key_store, _ApiKeyBulkDeleteStoreProtocol):
            await api_key_store.delete_for_user(user_id)
