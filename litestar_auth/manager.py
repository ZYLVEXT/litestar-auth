"""User-management business logic for litestar-auth."""

from __future__ import annotations

import dataclasses
import hashlib
import importlib
import logging
import re
import secrets
from collections.abc import Mapping as MappingABC
from collections.abc import Sequence as SequenceABC
from datetime import timedelta
from types import MappingProxyType
from typing import TYPE_CHECKING, Any, cast

from litestar_auth import config as _config
from litestar_auth._manager import _protocols as _manager_protocols
from litestar_auth._manager.account_tokens import (
    AccountTokenSecurityService,
    AccountTokensService,
    _AccountTokensManagerProtocol,
)
from litestar_auth._manager.construction import AccountTokenSecrets, SecretFactory, resolve_account_token_secrets
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
from litestar_auth._secrets_at_rest import FernetKey, FernetKeyring, SecretAtRestError, validate_fernet_key_id
from litestar_auth._superuser_role import DEFAULT_SUPERUSER_ROLE_NAME, normalize_superuser_role_name
from litestar_auth.config import RESET_PASSWORD_TOKEN_AUDIENCE, VERIFY_TOKEN_AUDIENCE, validate_secret_length
from litestar_auth.db.base import BaseOAuthAccountStore
from litestar_auth.exceptions import ConfigurationError
from litestar_auth.password import PasswordHelper
from litestar_auth.types import LoginIdentifier, UserProtocol

if TYPE_CHECKING:
    from collections.abc import Callable, Mapping
    from types import ModuleType

    import msgspec

    from litestar_auth.db.base import BaseUserStore

DEFAULT_VERIFY_TOKEN_LIFETIME = timedelta(hours=1)
DEFAULT_RESET_PASSWORD_TOKEN_LIFETIME = timedelta(hours=1)
ENCRYPTED_TOTP_SECRET_PREFIX = "fernet:"  # noqa: S105
_MASKED = "**********"
_LOGIN_IDENTIFIER_DIGEST_SIZE = 16
_FERNET_KEYRING_PAIR_SIZE = 2

type FernetKeyringConfigKeys = MappingABC[str, FernetKey]


@dataclasses.dataclass(frozen=True, slots=True)
class FernetKeyringConfig:
    """Public configuration contract for versioned Fernet keyrings."""

    active_key_id: str
    keys: FernetKeyringConfigKeys = dataclasses.field(repr=False)

    def __post_init__(self) -> None:
        """Validate the keyring shape and configured Fernet key material.

        Raises:
            ConfigurationError: If the keyring shape or key material is invalid.
        """
        normalized_keys = _normalize_fernet_keyring_config_keys(self.keys)
        try:
            keyring = FernetKeyring(active_key_id=self.active_key_id, keys=normalized_keys)
        except SecretAtRestError as exc:
            raise ConfigurationError(str(exc)) from exc
        object.__setattr__(self, "active_key_id", keyring.active_key_id)
        object.__setattr__(self, "keys", MappingProxyType(dict(keyring.keys)))

    def __repr__(self) -> str:
        """Return a representation that masks every configured Fernet key."""
        masked_keys = dict.fromkeys(self.keys, "***")
        return f"{type(self).__name__}(active_key_id={self.active_key_id!r}, keys={masked_keys!r})"

    __str__ = __repr__


@dataclasses.dataclass(frozen=True, slots=True)
class UserManagerSecurity[ID]:
    """Typed public contract for manager secrets and related security inputs.

    Production deployments should keep verification, reset-password, login
    telemetry, and TOTP secret roles separate even though distinct JWT audiences
    already scope each token flow independently. Password helper and validator
    fields belong in this security bundle when a deployment needs to override
    those defaults.
    """

    verification_token_secret: str | None = dataclasses.field(default=None, repr=False)
    reset_password_token_secret: str | None = dataclasses.field(default=None, repr=False)
    login_identifier_telemetry_secret: str | None = dataclasses.field(default=None, repr=False)
    totp_secret_key: str | None = dataclasses.field(default=None, repr=False)
    totp_secret_keyring: FernetKeyringConfig | None = dataclasses.field(default=None, repr=False)
    id_parser: Callable[[str], ID] | None = dataclasses.field(default=None, repr=False)
    password_helper: PasswordHelper | None = dataclasses.field(default=None, repr=False)
    password_validator: Callable[[str], None] | None = dataclasses.field(default=None, repr=False)

    def __post_init__(self) -> None:
        """Reject ambiguous TOTP secret-at-rest key inputs.

        Raises:
            ConfigurationError: If both one-key and keyring inputs are configured.
        """
        if self.totp_secret_key is None or self.totp_secret_keyring is None:
            return
        msg = "Configure TOTP secret encryption with totp_secret_key or totp_secret_keyring, not both."
        raise ConfigurationError(msg)

    def __repr__(self) -> str:
        """Return a repr that masks configured secret material."""
        return (
            "UserManagerSecurity("
            f"verification_token_secret={_mask_optional_secret(self.verification_token_secret)!r}, "
            f"reset_password_token_secret={_mask_optional_secret(self.reset_password_token_secret)!r}, "
            f"login_identifier_telemetry_secret="
            f"{_mask_optional_secret(self.login_identifier_telemetry_secret)!r}, "
            f"totp_secret_key={_mask_optional_secret(self.totp_secret_key)!r}, "
            f"totp_secret_keyring={self.totp_secret_keyring!r}, "
            f"id_parser={self.id_parser!r}, "
            f"password_helper={self.password_helper!r}, "
            f"password_validator={self.password_validator!r})"
        )


@dataclasses.dataclass(frozen=True, eq=False)
class _SecretValue:
    """Wraps a secret string so it is masked in repr/str output."""

    _value: str = dataclasses.field(repr=False)

    def get_secret_value(self) -> str:
        """Return the raw secret string."""
        return self._value

    def __repr__(self) -> str:
        return f"_SecretValue('{_MASKED}')"

    def __str__(self) -> str:
        return _MASKED


EMAIL_MAX_LENGTH = 320
_EMAIL_RE = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")
logger = logging.getLogger(__name__)
UserManagerUserProtocol = _manager_protocols.ManagedUserProtocol
AccountStateUserProtocol = _manager_protocols.AccountStateUserProtocol


def _normalize_fernet_keyring_config_keys(keys: object) -> dict[str, FernetKey]:
    """Return a validated key-id mapping for public keyring configuration.

    Raises:
        ConfigurationError: If key ids are malformed, duplicated, or not provided as pairs.
    """
    if isinstance(keys, MappingABC):
        items = tuple(keys.items())
    elif isinstance(keys, SequenceABC) and not isinstance(keys, (str, bytes, bytearray)):
        items = tuple(keys)
    else:
        msg = "FernetKeyringConfig keys must be a mapping or a sequence of key-id/key pairs."
        raise ConfigurationError(msg)

    normalized: dict[str, FernetKey] = {}
    for item in items:
        if (
            not isinstance(item, SequenceABC)
            or isinstance(item, (str, bytes, bytearray))
            or len(item) != _FERNET_KEYRING_PAIR_SIZE
        ):
            msg = "FernetKeyringConfig keys must contain key-id/key pairs."
            raise ConfigurationError(msg)
        key_id = item[0]
        key = item[1]
        if not isinstance(key_id, str):
            msg = "Fernet key ids must be strings."
            raise ConfigurationError(msg)
        try:
            validated_key_id = validate_fernet_key_id(key_id)
        except SecretAtRestError as exc:
            raise ConfigurationError(str(exc)) from exc
        if validated_key_id in normalized:
            msg = "Fernet keyring key ids must be unique."
            raise ConfigurationError(msg)
        if not isinstance(key, (str, bytes)):
            msg = "Configured Fernet key material is invalid."
            raise ConfigurationError(msg)
        normalized[validated_key_id] = key
    return normalized


def validate_user_manager_security_secret_roles_are_distinct(
    security: UserManagerSecurity[Any],
    *,
    totp_pending_secret: str | None = None,
    oauth_flow_cookie_secret: str | None = None,
) -> None:
    """Validate that manager-owned secret roles do not reuse unrelated key material."""
    totp_secret_values = _iter_totp_secret_role_values(security)
    if not totp_secret_values:
        _config.validate_secret_roles_are_distinct(
            _config.SecretRoleValues(
                verification_token_secret=security.verification_token_secret,
                reset_password_token_secret=security.reset_password_token_secret,
                login_identifier_telemetry_secret=security.login_identifier_telemetry_secret,
                totp_secret_key=None,
                totp_pending_secret=totp_pending_secret,
                oauth_flow_cookie_secret=oauth_flow_cookie_secret,
            ),
        )
        return

    for totp_secret_value in totp_secret_values:
        _config.validate_secret_roles_are_distinct(
            _config.SecretRoleValues(
                verification_token_secret=security.verification_token_secret,
                reset_password_token_secret=security.reset_password_token_secret,
                login_identifier_telemetry_secret=security.login_identifier_telemetry_secret,
                totp_secret_key=totp_secret_value,
                totp_pending_secret=totp_pending_secret,
                oauth_flow_cookie_secret=oauth_flow_cookie_secret,
            ),
        )


def _iter_totp_secret_role_values(security: UserManagerSecurity[Any]) -> tuple[str, ...]:
    """Return configured raw TOTP at-rest key material for distinct-role validation."""
    values: list[str] = []
    if security.totp_secret_key:
        values.append(security.totp_secret_key)
    if security.totp_secret_keyring is not None:
        values.extend(_coerce_fernet_key_secret_role_value(key) for key in security.totp_secret_keyring.keys.values())
    return tuple(values)


def _coerce_fernet_key_secret_role_value(key: FernetKey) -> str:
    """Return Fernet key material as text for existing distinct-secret validation."""
    return key.decode("utf-8") if isinstance(key, bytes) else key


def _get_dummy_hash(password_helper: PasswordHelper) -> str:
    """Return a freshly computed dummy password hash for the provided helper.

    ``BaseUserManager`` caches this value per instance so the same helper pipeline is
    reused for unknown-account timing equalization without depending on module-global
    mutable state.
    """
    return password_helper.hash(secrets.token_urlsafe(32))


def _mask_optional_secret(secret: str | None) -> str | None:
    """Return the standard masked placeholder when a secret is configured."""
    return _MASKED if secret is not None else None


def _login_identifier_digest(identifier: str, *, key: str) -> str:
    """Return a keyed, non-reversible digest for login-failure correlation."""
    normalized_identifier = identifier.strip().casefold()
    digest_key = hashlib.sha256(key.encode()).digest()
    return hashlib.blake2b(
        normalized_identifier.encode(),
        digest_size=_LOGIN_IDENTIFIER_DIGEST_SIZE,
        key=digest_key,
    ).hexdigest()


def _resolve_oauth_account_store[UP: UserProtocol[Any], ID](
    user_db: object,
) -> BaseOAuthAccountStore[UP, ID] | None:
    """Return an OAuth-account store when the user store also exposes that boundary."""
    if isinstance(user_db, BaseOAuthAccountStore):
        return user_db

    return None


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

    def __init__(  # noqa: PLR0913
        self: BaseUserManager[UP, ID],
        user_db: BaseUserStore[UP, ID],
        *,
        oauth_account_store: BaseOAuthAccountStore[UP, ID] | None = None,
        password_helper: PasswordHelper | None = None,
        security: UserManagerSecurity[ID] | None = None,
        verification_token_lifetime: timedelta = DEFAULT_VERIFY_TOKEN_LIFETIME,
        reset_password_token_lifetime: timedelta = DEFAULT_RESET_PASSWORD_TOKEN_LIFETIME,
        password_validator: Callable[[str], None] | None = None,
        reset_verification_on_email_change: bool = True,
        backends: tuple[object, ...] = (),
        login_identifier: LoginIdentifier = "email",
        superuser_role_name: str = DEFAULT_SUPERUSER_ROLE_NAME,
        unsafe_testing: bool = False,
    ) -> None:
        """Initialize the user manager.

        Args:
            user_db: Persistence backend used to load and update users.
            oauth_account_store: Optional persistence backend used for linked OAuth accounts.
            password_helper: Password hasher/verifier implementation. When omitted,
                :meth:`PasswordHelper.from_defaults` provides the library's Argon2-only
                default. Pass an explicit helper only when your application needs a
                non-default pwdlib policy.
            security: Typed bundle for verification/reset secrets, optional TOTP encryption key,
                and optional JWT ``sub`` parsing. Omitted fields default to ``None``. In
                production, use distinct values per secret role instead of reusing one value
                across verification, reset-password, and TOTP flows.
            verification_token_lifetime: Lifetime applied to verification tokens.
            reset_password_token_lifetime: Lifetime applied to password-reset tokens.
            password_validator: Optional callable used to validate plain-text passwords.
            reset_verification_on_email_change: Whether email changes should clear ``is_verified`` and
                trigger a new verification token hook.
            backends: Session-bound auth backends when constructed via ``LitestarAuth``;
                keeps credential updates aligned with the same backends used for request auth.
            login_identifier: Which field ``authenticate`` uses for credential lookup by default
                when ``login_identifier`` is not passed explicitly to ``authenticate``.
            superuser_role_name: Normalized role name that represents superuser privileges
                for plugin-managed guards.
            unsafe_testing: Explicit per-instance test-only override for flows that need
                generated fallback secrets or other single-process shortcuts. Do not
                enable this for production traffic.

        """
        resolved_security = security if security is not None else UserManagerSecurity()
        account_token_secrets = resolve_account_token_secrets(
            resolved_security,
            secret_factory=cast("SecretFactory", _SecretValue),
            warning_stacklevel=4,
            unsafe_testing=unsafe_testing,
        )
        resolved_verification_token_secret = account_token_secrets.verification_token_secret.get_secret_value()
        resolved_reset_password_token_secret = account_token_secrets.reset_password_token_secret.get_secret_value()
        resolved_login_identifier_telemetry_secret = resolved_security.login_identifier_telemetry_secret
        if resolved_login_identifier_telemetry_secret is not None and not unsafe_testing:
            validate_secret_length(
                resolved_login_identifier_telemetry_secret,
                label="login_identifier_telemetry_secret",
            )
        if not unsafe_testing:
            validate_user_manager_security_secret_roles_are_distinct(
                dataclasses.replace(
                    resolved_security,
                    verification_token_secret=resolved_verification_token_secret,
                    reset_password_token_secret=resolved_reset_password_token_secret,
                ),
            )
        self.user_db = user_db
        self.oauth_account_store = oauth_account_store or _resolve_oauth_account_store(user_db)
        self._account_token_secrets = account_token_secrets
        self.verification_token_secret = self._account_token_secrets.verification_token_secret
        self.reset_password_token_secret = self._account_token_secrets.reset_password_token_secret
        self.login_identifier_telemetry_secret = (
            _SecretValue(resolved_login_identifier_telemetry_secret)
            if resolved_login_identifier_telemetry_secret is not None
            else None
        )
        self.verification_token_lifetime = verification_token_lifetime
        self.reset_password_token_lifetime = reset_password_token_lifetime
        self.id_parser = resolved_security.id_parser
        self.password_validator = password_validator
        self.reset_verification_on_email_change = reset_verification_on_email_change
        self.totp_secret_key = resolved_security.totp_secret_key
        self.backends: tuple[object, ...] = backends
        self.login_identifier: LoginIdentifier = login_identifier
        self.superuser_role_name = normalize_superuser_role_name(superuser_role_name)
        self.unsafe_testing = unsafe_testing
        self.totp_secret_keyring = resolved_security.totp_secret_keyring
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
            verify_token_audience=VERIFY_TOKEN_AUDIENCE,
            reset_password_token_audience=RESET_PASSWORD_TOKEN_AUDIENCE,
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

    async def set_recovery_code_hashes(self, user: UP, hashes: tuple[str, ...]) -> UP:
        """Replace the active TOTP recovery-code hashes for a user.

        Returns:
            The updated user instance.
        """
        return cast("UP", await self.user_db.set_recovery_code_hashes(user, hashes))

    async def read_recovery_code_hashes(self, user: UP) -> tuple[str, ...]:
        """Return active TOTP recovery-code hashes for a user."""
        return cast("tuple[str, ...]", await self.user_db.read_recovery_code_hashes(user))

    async def consume_recovery_code_hash(self, user: UP, matched_hash: str) -> bool:
        """Atomically consume an active TOTP recovery-code hash.

        Returns:
            ``True`` when the hash was consumed, otherwise ``False``.
        """
        return cast("bool", await self.user_db.consume_recovery_code_hash(user, matched_hash))

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

    @staticmethod
    def _write_token_subject(
        *,
        subject: str,
        secret: str,
        audience: str,
        lifetime: timedelta,
        extra_claims: dict[str, Any] | None = None,
    ) -> str:
        """Sign a short-lived JWT bound to an arbitrary subject string.

        Returns:
            The encoded token.
        """
        return AccountTokenSecurityService.write_token_subject(
            subject=subject,
            secret=secret,
            audience=audience,
            lifetime=lifetime,
            extra_claims=extra_claims,
        )

    async def _invalidate_all_tokens(self, user: UP) -> None:
        """Invalidate all authentication tokens for a user when supported.

        This method iterates over any configured authentication backends
        attached to the manager instance and, when a backend strategy exposes
        ``invalidate_all_tokens``, delegates to it to revoke all persisted
        tokens for the user.
        """
        await self._user_lifecycle.invalidate_all_tokens(user)


def _load_cryptography_fernet() -> ModuleType:
    """Import the optional cryptography Fernet module on demand.

    Returns:
        The imported ``cryptography.fernet`` module.

    Raises:
        ImportError: If cryptography is not installed.
    """
    try:
        return importlib.import_module("cryptography.fernet")
    except ImportError as exc:
        msg = "Install litestar-auth[totp] to use TOTP secret encryption."
        raise ImportError(msg) from exc
