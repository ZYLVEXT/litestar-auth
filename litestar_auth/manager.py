"""User-management business logic for litestar-auth."""

from __future__ import annotations

import logging
from functools import partial
from typing import TYPE_CHECKING, Any, Unpack, cast, overload

from litestar_auth._manager import security as _manager_security
from litestar_auth._manager.account_tokens import (
    AccountTokenAudiences,
    AccountTokenSecurityService,
    AccountTokensService,
    _AccountTokensManagerProtocol,
)
from litestar_auth._manager.construction import (
    DEFAULT_RESET_PASSWORD_TOKEN_LIFETIME as _DEFAULT_RESET_PASSWORD_TOKEN_LIFETIME,
)
from litestar_auth._manager.construction import (
    DEFAULT_VERIFY_TOKEN_LIFETIME as _DEFAULT_VERIFY_TOKEN_LIFETIME,
)
from litestar_auth._manager.construction import (
    AccountTokenSecrets,
    BaseUserManagerConfig,
    BaseUserManagerOptions,
    ConstructorAttributes,
    get_dummy_hash,
    login_identifier_digest,
    resolve_oauth_account_store,
    resolve_secret_inputs,
    validate_secret_distinctness,
)
from litestar_auth._manager.hooks import UserManagerHooks
from litestar_auth._manager.security import (
    _SecretValue,
)
from litestar_auth._manager.totp_secrets import (
    TotpSecretsService,
    TotpSecretStoragePosture,
    _TotpSecretsManagerProtocol,
)
from litestar_auth._manager.user_lifecycle import (
    UserLifecycleService,
    _UserLifecycleManagerProtocol,
)
from litestar_auth._manager.user_policy import UserPolicy
from litestar_auth._optional_deps import require_cryptography_fernet
from litestar_auth._superuser_role import normalize_superuser_role_name
from litestar_auth.config import RESET_PASSWORD_TOKEN_AUDIENCE, VERIFY_TOKEN_AUDIENCE
from litestar_auth.password import PasswordHelper
from litestar_auth.types import LoginIdentifier, UserProtocol

if TYPE_CHECKING:
    from collections.abc import Callable, Mapping
    from types import ModuleType

    import msgspec

    from litestar_auth.db.base import BaseUserStore

ENCRYPTED_TOTP_SECRET_PREFIX = "fernet:"  # noqa: S105
DEFAULT_VERIFY_TOKEN_LIFETIME = _DEFAULT_VERIFY_TOKEN_LIFETIME
DEFAULT_RESET_PASSWORD_TOKEN_LIFETIME = _DEFAULT_RESET_PASSWORD_TOKEN_LIFETIME
FernetKeyringConfig = _manager_security.FernetKeyringConfig
UserManagerSecurity = _manager_security.UserManagerSecurity


logger = logging.getLogger(__name__)
_TOTP_SECRET_FERNET_INSTALL_HINT = "Install litestar-auth[totp] to use TOTP secret encryption."  # noqa: S105


_get_dummy_hash = get_dummy_hash
_login_identifier_digest = login_identifier_digest
_resolve_oauth_account_store = resolve_oauth_account_store


class BaseUserManager[UP: UserProtocol[Any], ID](  # noqa: PLR0904
    UserManagerHooks[UP],
    _UserLifecycleManagerProtocol[UP, ID],
    _AccountTokensManagerProtocol[UP, ID],
    _TotpSecretsManagerProtocol[UP],
):
    """Coordinate user persistence, password hashing, and account tokens.

    High-level flows stay available as convenience methods on the manager. Advanced
    integrations can use ``users``, ``tokens``, and ``totp`` to work against the
    decomposed internal services directly.
    """

    @overload
    def __init__(self, *, config: BaseUserManagerConfig[UP, ID]) -> None: ...  # pragma: no cover

    @overload
    def __init__(  # pragma: no cover
        self,
        user_db: BaseUserStore[UP, ID],
        **options: Unpack[BaseUserManagerOptions[UP, ID]],
    ) -> None: ...

    @overload
    def __init__(  # pragma: no cover
        self,
        *,
        user_db: BaseUserStore[UP, ID],
        **options: Unpack[BaseUserManagerOptions[UP, ID]],
    ) -> None: ...

    def __init__(
        self: BaseUserManager[UP, ID],
        user_db: BaseUserStore[UP, ID] | None = None,
        *,
        config: BaseUserManagerConfig[UP, ID] | None = None,
        **options: Unpack[BaseUserManagerOptions[UP, ID]],
    ) -> None:
        """Initialize the user manager.

        Args:
            user_db: Persistence backend used to load and update users.
            config: User-manager configuration object. Do not combine with
                ``user_db`` or keyword options.
            **options: Individual user-manager settings. Do not combine with
                ``config``.

        Raises:
            TypeError: If neither ``user_db`` nor ``config`` is provided.
            ValueError: If ``config`` is combined with ``user_db`` or keyword options.
        """
        if config is not None:
            if user_db is not None or options:
                msg = "Pass either BaseUserManagerConfig or user_db plus keyword options, not both."
                raise ValueError(msg)
            settings = config
        else:
            if user_db is None:
                msg = "BaseUserManager requires user_db or config."
                raise TypeError(msg)
            settings = BaseUserManagerConfig(user_db=user_db, **options)

        resolved_secret_inputs = resolve_secret_inputs(
            settings.security,
            secret_factory=cast("type[_SecretValue]", _SecretValue),
            unsafe_testing=settings.unsafe_testing,
        )
        validate_secret_distinctness(resolved_secret_inputs, unsafe_testing=settings.unsafe_testing)
        self._assign_constructor_attributes(
            ConstructorAttributes(
                user_db=settings.user_db,
                oauth_account_store=settings.oauth_account_store,
                resolved_secret_inputs=resolved_secret_inputs,
                verification_token_lifetime=settings.verification_token_lifetime,
                reset_password_token_lifetime=settings.reset_password_token_lifetime,
                password_validator=settings.password_validator,
                reset_verification_on_email_change=settings.reset_verification_on_email_change,
                backends=settings.backends,
                login_identifier=settings.login_identifier,
                superuser_role_name=settings.superuser_role_name,
                unsafe_testing=settings.unsafe_testing,
            ),
        )
        self._build_internal_services(settings.password_helper)

    def _assign_constructor_attributes(
        self,
        settings: ConstructorAttributes[UP, ID],
    ) -> None:
        """Assign constructor-provided dependencies and resolved configuration."""
        resolved_secret_inputs = settings.resolved_secret_inputs
        resolved_security = resolved_secret_inputs.security
        self.user_db = settings.user_db
        self.oauth_account_store = settings.oauth_account_store or resolve_oauth_account_store(settings.user_db)
        self._account_token_secrets = resolved_secret_inputs.account_token_secrets
        self.verification_token_secret = self._account_token_secrets.verification_token_secret
        self.reset_password_token_secret = self._account_token_secrets.reset_password_token_secret
        self.login_identifier_telemetry_secret = (
            _SecretValue(resolved_secret_inputs.login_identifier_telemetry_secret)
            if resolved_secret_inputs.login_identifier_telemetry_secret is not None
            else None
        )
        self.verification_token_lifetime = settings.verification_token_lifetime
        self.reset_password_token_lifetime = settings.reset_password_token_lifetime
        self.id_parser = resolved_security.id_parser
        self.password_validator = settings.password_validator
        self.reset_verification_on_email_change = settings.reset_verification_on_email_change
        self.totp_secret_key = resolved_security.totp_secret_key
        self._totp_recovery_code_lookup_secret = resolved_security.totp_recovery_code_lookup_secret
        self.backends: tuple[object, ...] = settings.backends
        self.login_identifier: LoginIdentifier = settings.login_identifier
        self.superuser_role_name = normalize_superuser_role_name(settings.superuser_role_name)
        self.unsafe_testing = settings.unsafe_testing
        self.totp_secret_keyring = resolved_security.totp_secret_keyring

    def _build_internal_services(self, password_helper: PasswordHelper | None) -> None:
        """Instantiate the services backing the manager facade."""
        resolved_password_helper = password_helper or PasswordHelper.from_defaults()
        self.policy = UserPolicy(
            password_helper=resolved_password_helper,
            password_validator=self.password_validator,
        )
        self.password_helper = self.policy.password_helper
        self._dummy_password_hash: str | None = None
        self._dummy_password_hash_helper: PasswordHelper | None = None
        self._user_lifecycle = UserLifecycleService(self, policy=self.policy)
        self._account_token_security = AccountTokenSecurityService(
            self,
            logger=logger,
            reset_password_token_audience=RESET_PASSWORD_TOKEN_AUDIENCE,
        )
        self._account_tokens = AccountTokensService(
            self,
            audiences=AccountTokenAudiences(
                verify=VERIFY_TOKEN_AUDIENCE,
                reset_password=RESET_PASSWORD_TOKEN_AUDIENCE,
            ),
            token_security=self._account_token_security,
            logger=logger,
            policy=self.policy,
        )
        if self.totp_secret_keyring is None:
            self._totp_secrets = cast(
                "TotpSecretsService[UP]",
                TotpSecretsService(self, prefix=ENCRYPTED_TOTP_SECRET_PREFIX),
            )
        else:
            self._totp_secrets = cast(
                "TotpSecretsService[UP]",
                TotpSecretsService(
                    self,
                    prefix=ENCRYPTED_TOTP_SECRET_PREFIX,
                    active_key_id=self.totp_secret_keyring.active_key_id,
                    keys=self.totp_secret_keyring.keys,
                ),
            )

    @property
    def account_token_secrets(self) -> AccountTokenSecrets:
        """Return the resolved verify/reset secret bundle used by account-token services."""
        return self._account_token_secrets

    @property
    def totp_secret_storage_posture(self) -> TotpSecretStoragePosture:
        """Return the explicit storage contract for persisted TOTP secrets."""
        return self._totp_secrets.storage_posture

    @property
    def recovery_code_lookup_secret(self) -> bytes | None:
        """Return the configured TOTP recovery-code lookup HMAC key."""
        if self._totp_recovery_code_lookup_secret is None:
            return None
        return self._totp_recovery_code_lookup_secret.encode("utf-8")

    @property
    def users(self) -> UserLifecycleService[UP, ID]:
        """Return the lifecycle service backing CRUD and authentication flows."""
        return self._user_lifecycle

    @property
    def tokens(self) -> AccountTokensService[UP, ID]:
        """Return the token service backing verify and reset flows."""
        return self._account_tokens

    @property
    def totp(self) -> TotpSecretsService[UP]:
        """Return the TOTP secret service backing storage and decryption flows."""
        return self._totp_secrets

    def _get_dummy_hash(self) -> str:
        """Return the manager-scoped dummy hash used for unknown-user timing equalization."""
        if self._dummy_password_hash is None or self._dummy_password_hash_helper is not self.password_helper:
            self._dummy_password_hash = _get_dummy_hash(self.password_helper)
            self._dummy_password_hash_helper = self.password_helper
        return self._dummy_password_hash

    async def get(self, user_id: ID) -> UP | None:
        """Return a user by identifier.

        Returns:
            The matching user when one exists, otherwise ``None``.
        """
        return await self._user_lifecycle.get(user_id)

    async def create(
        self,
        user_create: msgspec.Struct | Mapping[str, Any],
        *,
        safe: bool = True,
        allow_privileged: bool = False,
    ) -> UP:
        """Create a new user, hashing the provided password before persistence.

        Privileged fields (``is_active``, ``is_verified``, ``roles``) are
        silently dropped unless ``allow_privileged=True``. With ``safe=True``
        (default), any field outside ``{"email", "password"}`` is also
        dropped.

        Returns:
            The newly created user.
        """
        user = await self._user_lifecycle.create(user_create, safe=safe, allow_privileged=allow_privileged)
        logger.info("User registered", extra={"event": "register", "user_id": str(user.id)})
        return user

    async def list_users(self, *, offset: int, limit: int) -> tuple[list[UP], int]:
        """Return paginated users and the total available count."""
        return await self._user_lifecycle.list_users(offset=offset, limit=limit)

    async def authenticate(
        self,
        identifier: str,
        password: str,
        *,
        login_identifier: LoginIdentifier | None = None,
    ) -> UP | None:
        """Return the matching user when credentials are valid.

        After successful verification, if the stored hash is deprecated under the active
        helper policy, the password hash is upgraded to the current algorithm in the DB.
        If the DB update fails, login still succeeds without upgrading the hash.

        Args:
            identifier: Email or username string, depending on ``login_identifier``.
            password: Plain-text password.
            login_identifier: Lookup mode; defaults to :attr:`login_identifier` on this manager.
        """
        mode = login_identifier if login_identifier is not None else self.login_identifier
        user = await self._user_lifecycle.authenticate(
            identifier,
            password,
            login_identifier=mode,
            dummy_hash=self._get_dummy_hash(),
            logger=logger,
        )
        if user is None:
            log_extra: dict[str, object] = {
                "event": "login_failed",
                "login_identifier_type": mode,
            }
            if self.login_identifier_telemetry_secret is not None:
                log_extra["identifier_digest"] = _login_identifier_digest(
                    identifier,
                    key=self.login_identifier_telemetry_secret.get_secret_value(),
                )
            logger.warning(
                "User login failed",
                extra=log_extra,
            )
            return None

        logger.info("User login succeeded", extra={"event": "login", "user_id": str(user.id)})
        return user

    def require_account_state(self, user: UP, *, require_verified: bool = False) -> None:  # noqa: PLR6301
        """Validate account-state policy for authenticated flows.

        Args:
            user: User to validate.
            require_verified: When ``True``, also enforce ``is_verified``.
        """
        UserPolicy.require_account_state(user, require_verified=require_verified)

    async def verify(self, token: str) -> UP:
        """Mark a user as verified using a signed verification token.

        Returns:
            The verified user instance.
        """
        return await self._account_tokens.verify(token)

    async def request_verify_token(self, email: str) -> None:
        """Generate a new verification token for an existing unverified user."""
        await self._account_tokens.request_verify_token(email)

    async def forgot_password(self, email: str) -> None:
        """Trigger the forgot-password flow without revealing whether a user exists."""
        await self._account_tokens.forgot_password(email, dummy_hash=self._get_dummy_hash())

    async def reset_password(self, token: str, password: str) -> UP:
        """Reset a user's password using a signed reset token.

        Returns:
            The updated user instance.
        """
        return await self._account_tokens.reset_password(token, password)

    async def set_totp_secret(self, user: UP, secret: str | None) -> UP:
        """Store or clear the TOTP secret directly, bypassing None-filtering.

        Args:
            user: The user whose TOTP secret should be updated.
            secret: New secret string, or ``None`` to disable 2FA.

        Returns:
            The updated user instance.
        """
        return await self._totp_secrets.set_secret(
            user,
            secret,
            load_cryptography_fernet=_load_cryptography_fernet,
        )

    async def read_totp_secret(self, secret: str | None) -> str | None:
        """Return a plain-text TOTP secret from storage.

        Returns:
            Plain-text secret, or ``None`` when 2FA is disabled.
        """
        return await self._totp_secrets.read_secret(secret, load_cryptography_fernet=_load_cryptography_fernet)

    def totp_secret_requires_reencrypt(self, secret: str | None) -> bool:
        """Return whether a stored TOTP secret should be rewritten with the active key."""
        return self._totp_secrets.requires_reencrypt(
            secret,
            load_cryptography_fernet=_load_cryptography_fernet,
        )

    def reencrypt_totp_secret_for_storage(self, secret: str | None) -> str | None:
        """Return a stored TOTP secret rewritten with the active key."""
        return self._totp_secrets.reencrypt_secret_for_storage(
            secret,
            load_cryptography_fernet=_load_cryptography_fernet,
        )

    async def set_recovery_code_hashes(self, user: UP, code_index: dict[str, str]) -> UP:
        """Replace the active TOTP recovery-code lookup index for a user.

        Returns:
            The updated user instance.
        """
        return cast("UP", await self.user_db.set_recovery_code_hashes(user, code_index))

    async def find_recovery_code_hash_by_lookup(self, user: UP, lookup_hex: str) -> str | None:
        """Return the active recovery-code hash matching ``lookup_hex``."""
        return cast("str | None", await self.user_db.find_recovery_code_hash_by_lookup(user, lookup_hex))

    async def consume_recovery_code_by_lookup(self, user: UP, lookup_hex: str) -> bool:
        """Atomically consume an active TOTP recovery-code lookup entry.

        Returns:
            ``True`` when the lookup entry was consumed, otherwise ``False``.
        """
        return cast("bool", await self.user_db.consume_recovery_code_by_lookup(user, lookup_hex))

    def _prepare_totp_secret_for_storage(self, secret: str | None) -> str | None:
        """Return the database representation for a TOTP secret."""
        return self._totp_secrets.prepare_secret_for_storage(
            secret,
            load_cryptography_fernet=_load_cryptography_fernet,
        )

    async def update(
        self,
        user_update: msgspec.Struct | Mapping[str, Any],
        user: UP,
        *,
        allow_privileged: bool = False,
    ) -> UP:
        """Update mutable user fields, hashing passwords when provided.

        Fields with ``None`` values in *user_update* are treated as absent and
        will **not** overwrite existing data.  To explicitly clear a nullable
        field, use a dedicated method (e.g. ``set_totp_secret(user, None)``).

        Privileged fields such as ``is_active``, ``is_verified``, and ``roles``
        are rejected unless
        ``allow_privileged=True`` is passed explicitly.

        Returns:
            The updated user, or the original user when there are no changes.
        """
        return await self._user_lifecycle.update(user_update, user, allow_privileged=allow_privileged)

    async def delete(self, user_id: ID) -> None:
        """Delete a user permanently and run the post-delete hook."""
        await self._user_lifecycle.delete(user_id)

    def write_verify_token(self, user: UP) -> str:
        """Return a signed email-verification token for a user.

        Returns:
            A short-lived verification token.
        """
        return self._account_tokens.write_verify_token(user)

    _write_token_subject = staticmethod(AccountTokenSecurityService.write_token_subject)

    async def _invalidate_all_tokens(self, user: UP) -> None:
        """Invalidate all authentication tokens for a user when supported.

        This method iterates over any configured authentication backends
        attached to the manager instance and, when a backend strategy exposes
        ``invalidate_all_tokens``, delegates to it to revoke all persisted
        tokens for the user.
        """
        await self._user_lifecycle.invalidate_all_tokens(user)


_load_cryptography_fernet = cast(
    "Callable[[], ModuleType]",
    partial(require_cryptography_fernet, install_hint=_TOTP_SECRET_FERNET_INSTALL_HINT),
)
