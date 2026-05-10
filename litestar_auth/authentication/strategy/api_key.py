"""API-key authentication strategy."""

from __future__ import annotations

import contextvars
from collections.abc import Callable
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import TYPE_CHECKING, Any, NotRequired, Protocol, Required, TypedDict, Unpack, cast, overload, override

from litestar_auth._secrets_at_rest import FernetKeyring, SecretAtRestError
from litestar_auth.authentication.strategy._api_key_format import API_KEY_PREFIX, api_key_secret_matches, parse_api_key
from litestar_auth.authentication.strategy.base import Strategy, UserManagerProtocol
from litestar_auth.authentication.transport._api_key_signing import (
    API_KEY_HMAC_SCHEME,
    classify_signed_request_skew,
    get_current_signed_api_key_request,
    signature_matches,
)
from litestar_auth.config import validate_production_secret
from litestar_auth.exceptions import ConfigurationError, ErrorCode, TokenError
from litestar_auth.types import UserProtocol

if TYPE_CHECKING:
    from litestar.connection import ASGIConnection

    from litestar_auth.authentication.strategy._api_key_nonce_store import ApiKeyNonceStore
    from litestar_auth.authentication.transport._api_key_signing import SignedApiKeyRequest
    from litestar_auth.db.base import BaseApiKeyStore

type ApiKeyScopeAuthority = Callable[[ASGIConnection[Any, Any, Any, Any], frozenset[str]], bool]
_SIGNED_NONCE_FAILURE_CODE: contextvars.ContextVar[ErrorCode | None] = contextvars.ContextVar(
    "litestar_auth_api_key_signed_nonce_failure_code",
    default=None,
)


class _ApiKeyRow(Protocol):
    """Persistence fields required by API-key verification."""

    user_id: object
    key_id: str
    hashed_secret: bytes
    scopes: list[str]
    prefix_env: str
    expires_at: datetime | None
    revoked_at: datetime | None
    encrypted_secret: bytes | None
    signing_required: bool


@dataclass(frozen=True, slots=True)
class ApiKeyContext:
    """Authentication context exposed as ``request.auth`` for API-key requests."""

    key_id: str
    scopes: tuple[str, ...]
    prefix_env: str
    scope_subset_check: bool = True
    scope_authority: ApiKeyScopeAuthority | None = None


@dataclass(frozen=True, slots=True)
class ApiKeyAuthenticationResult[UP: UserProtocol[Any]]:
    """Resolved API-key user plus request authentication context."""

    user: UP
    context: ApiKeyContext


@dataclass(frozen=True, slots=True)
class ApiKeyStrategyConfig:
    """Configuration for :class:`ApiKeyStrategy`."""

    api_key_store: BaseApiKeyStore[Any, Any]
    api_key_hash_secret: str
    prefix_env: str | None = None
    prefix: str = API_KEY_PREFIX
    scope_subset_check: bool = True
    scope_authority: ApiKeyScopeAuthority | None = None
    signing_skew_seconds: int = 300
    nonce_store: ApiKeyNonceStore | None = None
    secret_encryption_keyring: FernetKeyring | None = None
    unsafe_testing: bool = False


class ApiKeyStrategyOptions(TypedDict):
    """Keyword options accepted by :class:`ApiKeyStrategy`."""

    api_key_store: Required[BaseApiKeyStore[Any, Any]]
    api_key_hash_secret: Required[str]
    prefix_env: NotRequired[str | None]
    prefix: NotRequired[str]
    scope_subset_check: NotRequired[bool]
    scope_authority: NotRequired[ApiKeyScopeAuthority | None]
    signing_skew_seconds: NotRequired[int]
    nonce_store: NotRequired[ApiKeyNonceStore | None]
    secret_encryption_keyring: NotRequired[FernetKeyring | None]
    unsafe_testing: NotRequired[bool]


class ApiKeyStrategy[UP: UserProtocol[Any], ID](Strategy[UP, ID]):
    """Verify API-key credentials against indexed persisted key rows."""

    @overload
    def __init__(self, *, config: ApiKeyStrategyConfig) -> None:
        pass  # pragma: no cover

    @overload
    def __init__(self, **options: Unpack[ApiKeyStrategyOptions]) -> None:
        pass  # pragma: no cover

    def __init__(
        self,
        *,
        config: ApiKeyStrategyConfig | None = None,
        **options: Unpack[ApiKeyStrategyOptions],
    ) -> None:
        """Initialize the API-key strategy.

        Raises:
            ValueError: If ``config`` and keyword options are combined.
            ConfigurationError: If ``api_key_hash_secret`` is not production-safe.
        """
        if config is not None and options:
            msg = "Pass either ApiKeyStrategyConfig or keyword options, not both."
            raise ValueError(msg)
        settings = ApiKeyStrategyConfig(**options) if config is None else config
        try:
            validate_production_secret(
                settings.api_key_hash_secret,
                label="ApiKeyStrategy api_key_hash_secret",
                unsafe_testing=settings.unsafe_testing,
            )
        except ConfigurationError as exc:
            raise ConfigurationError(str(exc)) from exc

        self.api_key_store = settings.api_key_store
        self._api_key_hash_secret = settings.api_key_hash_secret.encode()
        self.prefix_env = settings.prefix_env
        self.prefix = settings.prefix
        self.scope_subset_check = settings.scope_subset_check
        self.scope_authority = settings.scope_authority
        self.signing_skew_seconds = settings.signing_skew_seconds
        self.nonce_store = settings.nonce_store
        self.secret_encryption_keyring = settings.secret_encryption_keyring
        self.unsafe_testing = settings.unsafe_testing

    async def read_token_with_context(  # noqa: PLR0911
        self,
        token: str | None,
        user_manager: UserManagerProtocol[UP, ID],
    ) -> ApiKeyAuthenticationResult[UP] | None:
        """Resolve a user and API-key context from a canonical API-key token.

        Returns:
            Resolved user and API-key context, or ``None`` when verification fails.
        """
        if token is None:
            return None
        if token == API_KEY_HMAC_SCHEME:
            return await self._read_signed_request(user_manager)

        parsed = parse_api_key(token, expected_prefix_env=self.prefix_env, prefix=self.prefix)
        if parsed is None:
            return None

        api_key = await self.api_key_store.get_by_key_id(parsed.key_id, include_inactive=True)
        if api_key is None or not self._api_key_can_be_verified(api_key, prefix_env=parsed.prefix_env):
            return None
        if getattr(api_key, "signing_required", False):
            return None
        if not api_key_secret_matches(
            stored_digest=api_key.hashed_secret,
            api_key_hash_secret=self._api_key_hash_secret,
            secret=parsed.secret,
        ):
            return None

        user = await user_manager.get(cast("ID", api_key.user_id))
        if user is None:
            return None
        return ApiKeyAuthenticationResult(
            user=user,
            context=ApiKeyContext(
                key_id=api_key.key_id,
                scopes=tuple(api_key.scopes),
                prefix_env=api_key.prefix_env,
                scope_subset_check=self.scope_subset_check,
                scope_authority=self.scope_authority,
            ),
        )

    @override
    async def read_token(self, token: str | None, user_manager: object) -> UP | None:
        """Resolve a user from an API-key token.

        Returns:
            Resolved user, or ``None`` when verification fails.
        """
        result = await self.read_token_with_context(
            token,
            user_manager=cast("UserManagerProtocol[UP, ID]", user_manager),
        )
        return None if result is None else result.user

    @override
    async def write_token(self, user: UP) -> str:
        """Reject login-token issuance because API keys are manager-issued credentials.

        Raises:
            TokenError: Always, because API keys are not login-flow tokens.
        """
        del user
        msg = "ApiKeyStrategy does not issue login tokens."
        raise TokenError(msg)

    @override
    async def destroy_token(self, token: str, user: UP) -> None:
        """Do nothing because API-key revocation is handled by API-key management flows."""
        del token, user

    @staticmethod
    def _api_key_can_be_verified(api_key: _ApiKeyRow, *, prefix_env: str) -> bool:
        """Return whether a row matches the parsed public fields and active-state checks."""
        return api_key.prefix_env == prefix_env and ApiKeyStrategy._api_key_is_active(api_key)

    @staticmethod
    def _api_key_is_active(api_key: _ApiKeyRow) -> bool:
        """Return whether a persisted API-key row is active at the current time."""
        if api_key.revoked_at is not None:
            return False
        if api_key.expires_at is None:
            return True
        expires_at = api_key.expires_at
        if expires_at.tzinfo is None:
            expires_at = expires_at.replace(tzinfo=UTC)
        return expires_at > datetime.now(tz=UTC)

    async def _read_signed_request(
        self,
        user_manager: UserManagerProtocol[UP, ID],
    ) -> ApiKeyAuthenticationResult[UP] | None:
        _SIGNED_NONCE_FAILURE_CODE.set(None)
        signed_request = get_current_signed_api_key_request()
        if signed_request is None:
            return None
        api_key = await self._get_verifiable_signed_api_key(signed_request.key_id)
        if api_key is None:
            return None
        secret = self._decrypt_signing_secret(api_key)
        if secret is None or self._signed_request_has_skew(signed_request):
            return None
        if not self._signed_request_signature_matches(signed_request, secret=secret):
            return None
        return await self._signed_authentication_result(user_manager, api_key, signed_request)

    async def _signed_authentication_result(
        self,
        user_manager: UserManagerProtocol[UP, ID],
        api_key: _ApiKeyRow,
        signed_request: SignedApiKeyRequest,
    ) -> ApiKeyAuthenticationResult[UP] | None:
        """Return the signed API-key authentication result after user and nonce checks."""
        user = await user_manager.get(cast("ID", api_key.user_id))
        if user is None:
            return None
        if not await self._consume_signed_nonce(api_key, signed_request):
            return None
        return self._api_key_authentication_result(user, api_key)

    async def _get_verifiable_signed_api_key(self, key_id: str) -> _ApiKeyRow | None:
        """Return an active signing-required API-key row matching this strategy."""
        api_key = await self.api_key_store.get_by_key_id(key_id, include_inactive=True)
        if api_key is None:
            return None
        if not self._api_key_is_active(api_key) or not getattr(api_key, "signing_required", False):
            return None
        if self.prefix_env is not None and api_key.prefix_env != self.prefix_env:
            return None
        return api_key

    def _signed_request_has_skew(self, signed_request: SignedApiKeyRequest) -> bool:
        """Return whether a signed request timestamp is outside the accepted skew."""
        return (
            classify_signed_request_skew(
                signed_request,
                now=datetime.now(tz=UTC),
                skew_seconds=self.signing_skew_seconds,
            )
            is not None
        )

    async def _consume_signed_nonce(self, api_key: _ApiKeyRow, signed_request: SignedApiKeyRequest) -> bool:
        """Return whether the signed request nonce was accepted as new."""
        nonce_store = self.nonce_store
        if nonce_store is None:
            return False
        return await self._mark_signed_nonce_used(
            nonce_store,
            key_id=api_key.key_id,
            nonce=signed_request.nonce,
        )

    def _api_key_authentication_result(self, user: UP, api_key: _ApiKeyRow) -> ApiKeyAuthenticationResult[UP]:
        """Return the authentication result for a verified API-key row."""
        return ApiKeyAuthenticationResult(
            user=user,
            context=ApiKeyContext(
                key_id=api_key.key_id,
                scopes=tuple(api_key.scopes),
                prefix_env=api_key.prefix_env,
                scope_subset_check=self.scope_subset_check,
                scope_authority=self.scope_authority,
            ),
        )

    @staticmethod
    def _signed_request_signature_matches(signed_request: SignedApiKeyRequest, *, secret: str) -> bool:
        """Return whether the request HMAC matches the canonical request."""
        return signature_matches(
            secret=secret,
            canonical_request=signed_request.canonical_request,
            signature=signed_request.signature,
        )

    async def _mark_signed_nonce_used(self, nonce_store: ApiKeyNonceStore, *, key_id: str, nonce: str) -> bool:
        nonce_result = await nonce_store.mark_used(
            key_id=key_id,
            nonce=nonce,
            ttl_seconds=max(self.signing_skew_seconds * 2, 1),
        )
        if nonce_result.stored:
            return True
        if nonce_result.rejected_as_replay:
            _SIGNED_NONCE_FAILURE_CODE.set(ErrorCode.API_KEY_SIGNATURE_NONCE_REPLAY)
        return False

    def _decrypt_signing_secret(self, api_key: _ApiKeyRow) -> str | None:
        encrypted_secret = getattr(api_key, "encrypted_secret", None)
        if encrypted_secret is None or self.secret_encryption_keyring is None:
            return None
        try:
            return self.secret_encryption_keyring.decrypt(encrypted_secret.decode("utf-8"))
        except (SecretAtRestError, UnicodeDecodeError):
            return None

    async def classify_failure_code(self, token: str | None) -> ErrorCode:  # noqa: PLR0911
        """Return the most specific API-key authentication failure code for ``token``."""
        if token == API_KEY_HMAC_SCHEME:
            return await self._classify_signed_failure_code()
        if token is None:
            return ErrorCode.API_KEY_INVALID
        parsed = parse_api_key(token, expected_prefix_env=self.prefix_env, prefix=self.prefix)
        if parsed is None:
            return ErrorCode.API_KEY_INVALID
        api_key = await self.api_key_store.get_by_key_id(parsed.key_id, include_inactive=True)
        if api_key is None or api_key.prefix_env != parsed.prefix_env:
            return ErrorCode.API_KEY_INVALID
        if getattr(api_key, "signing_required", False):
            return ErrorCode.API_KEY_SIGNATURE_INVALID
        if api_key.revoked_at is not None:
            return ErrorCode.API_KEY_REVOKED
        if _expires_in_past(api_key.expires_at):
            return ErrorCode.API_KEY_EXPIRED
        if not api_key_secret_matches(
            stored_digest=api_key.hashed_secret,
            api_key_hash_secret=self._api_key_hash_secret,
            secret=parsed.secret,
        ):
            return ErrorCode.API_KEY_INVALID
        return ErrorCode.API_KEY_INVALID

    async def _classify_signed_failure_code(self) -> ErrorCode:
        signed_request = get_current_signed_api_key_request()
        if signed_request is None:
            return ErrorCode.API_KEY_SIGNATURE_INVALID
        api_key = await self.api_key_store.get_by_key_id(signed_request.key_id, include_inactive=True)
        row_failure_code = self._classify_signed_api_key_row(api_key)
        if row_failure_code is not None:
            return row_failure_code
        api_key = cast("_ApiKeyRow", api_key)
        if self._signed_request_has_skew(signed_request):
            return ErrorCode.API_KEY_SIGNATURE_TIMESTAMP_SKEW
        secret = self._decrypt_signing_secret(api_key)
        if secret is None or not self._signed_request_signature_matches(signed_request, secret=secret):
            return ErrorCode.API_KEY_SIGNATURE_INVALID
        if _SIGNED_NONCE_FAILURE_CODE.get() is ErrorCode.API_KEY_SIGNATURE_NONCE_REPLAY:
            return ErrorCode.API_KEY_SIGNATURE_NONCE_REPLAY
        return ErrorCode.API_KEY_SIGNATURE_INVALID

    def _classify_signed_api_key_row(self, api_key: _ApiKeyRow | None) -> ErrorCode | None:
        """Return a failure code for signed API-key row state, if the row is unusable."""
        if api_key is None:
            return ErrorCode.API_KEY_SIGNATURE_INVALID
        if self.prefix_env is not None and api_key.prefix_env != self.prefix_env:
            return ErrorCode.API_KEY_SIGNATURE_INVALID
        if api_key.revoked_at is not None:
            return ErrorCode.API_KEY_REVOKED
        if _expires_in_past(api_key.expires_at):
            return ErrorCode.API_KEY_EXPIRED
        if not getattr(api_key, "signing_required", False):
            return ErrorCode.API_KEY_SIGNATURE_INVALID
        return None


def _expires_in_past(expires_at: datetime | None) -> bool:
    if expires_at is None:
        return False
    aware_expires_at = expires_at.replace(tzinfo=UTC) if expires_at.tzinfo is None else expires_at.astimezone(UTC)
    return aware_expires_at <= datetime.now(tz=UTC)
