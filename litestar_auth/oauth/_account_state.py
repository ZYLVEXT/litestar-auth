"""OAuth account-state validation helpers."""

from __future__ import annotations

import litestar_auth._account_state as _shared_account_state
from litestar_auth.exceptions import InactiveUserError, UnverifiedUserError

_ACCOUNT_STATE_ERROR_TYPES = _shared_account_state.AccountStateErrorTypes(
    inactive_error=InactiveUserError,
    unverified_error=UnverifiedUserError,
)


def require_account_state(user: object, *, user_manager: object) -> None:
    """Validate the user account state and map failures to client-facing errors."""
    _shared_account_state.require_account_state_with_client_error(
        user,
        require_verified=False,
        user_manager=user_manager,
        error_types=_ACCOUNT_STATE_ERROR_TYPES,
    )
