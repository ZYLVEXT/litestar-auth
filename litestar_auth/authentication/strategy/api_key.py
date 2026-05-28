"""API-key authentication strategy."""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass
from datetime import UTC, datetime
from enum import StrEnum, auto
from typing import (
    TYPE_CHECKING,
    Any,
    NotRequired,
    Protocol,
    Required,
    TypedDict,
    Unpack,
    cast,
    overload,
    override,
    runtime_checkable,
)

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


@runtime_checkable
class _ApiKeyRow[ID](Protocol):
    """Persistence fields required by API-key verification."""

    user_id: ID
    key_id: str
    hashed_secret: bytes
    scopes: list[str]
    prefix_env: str
    expires_at: datetime | None
    revoked_at: datetime | None


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


class ApiKeyFailureReason(StrEnum):
    """Internal API-key authentication failure taxonomy."""

    @staticmethod
    def _generate_next_value_(name: str, start: int, count: int, last_values: list[str]) -> str:  # noqa: ARG004
        return name

    INVALID = auto()
    REVOKED = auto()
    EXPIRED = auto()
    SIGNATURE_INVALID = auto()
    SIGNATURE_TIMESTAMP_SKEW = auto()
    SIGNATURE_NONCE_REPLAY = auto()


@dataclass(frozen=True, slots=True)
class ApiKeyAuthenticationAttempt[UP: UserProtocol[Any]]:
    """API-key authentication result plus deterministic failure reason."""

    result: ApiKeyAuthenticationResult[UP] | None
    failure_reason: ApiKeyFailureReason | None


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
    def __init__(self, *, config: ApiKeyStrategyConfig) -> None: ...

    @overload
    def __init__(self, **options: Unpack[ApiKeyStrategyOptions]) -> None: ...

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

    async def read_token_attempt(
        self,
        token: str | None,
        user_manager: UserManagerProtocol[UP, ID],
    ) -> ApiKeyAuthenticationAttempt[UP]:
        """Resolve an API-key request and preserve the failed reason when rejected.

        Returns:
            Successful authentication result, or ``None`` plus a typed failure reason.
        """
        if token is None:
            return _api_key_failure(ApiKeyFailureReason.INVALID)
        if token == API_KEY_HMAC_SCHEME:
            return await self._read_signed_request(user_manager)
        return await self._read_bearer_api_key(token, user_manager)

    async def read_token_with_context(
        self,
        token: str | None,
        user_manager: UserManagerProtocol[UP, ID],
    ) -> ApiKeyAuthenticationResult[UP] | None:
        """Resolve a user and API-key context from a canonical API-key token.

        Returns:
            Resolved user and API-key context, or ``None`` when verification fails.
        """
        return (await self.read_token_attempt(token, user_manager)).result

    async def _read_bearer_api_key(  # noqa: PLR0911
        self,
        token: str,
        user_manager: UserManagerProtocol[UP, ID],
    ) -> ApiKeyAuthenticationAttempt[UP]:
        """Resolve a bearer API key or return its failure reason.

        Returns:
            Successful authentication result, or ``None`` plus a typed failure reason.
        """
        parsed = parse_api_key(token, expected_prefix_env=self.prefix_env, prefix=self.prefix)
        if parsed is None:
            return _api_key_failure(ApiKeyFailureReason.INVALID)

        api_key = await self._lookup_api_key(parsed.key_id)
        if api_key is None or api_key.prefix_env != parsed.prefix_env:
            return _api_key_failure(ApiKeyFailureReason.INVALID)
        if getattr(api_key, "signing_required", False):
            return _api_key_failure(ApiKeyFailureReason.SIGNATURE_INVALID)
        row_failure = self._classify_bearer_api_key_row(api_key)
        if row_failure is not None:
            return _api_key_failure(row_failure)
        if not api_key_secret_matches(
            stored_digest=api_key.hashed_secret,
            api_key_hash_secret=self._api_key_hash_secret,
            secret=parsed.secret,
        ):
            return _api_key_failure(ApiKeyFailureReason.INVALID)

        user = await user_manager.get(api_key.user_id)
        if user is None:
            return _api_key_failure(ApiKeyFailureReason.INVALID)
        return _api_key_success(self._api_key_authentication_result(user, api_key))

    @override
    async def read_token(self, token: str | None, user_manager: object) -> UP | None:
        """Resolve a user from an API-key token.

        Returns:
            Resolved user, or ``None`` when verification fails.
        """
        # StrategyProtocol accepts object for pluggability; this concrete strategy requires the user-manager contract.
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
        msg = "ApiKeyStrategy does not issue login tokens."
        raise TokenError(msg)

    @override
    async def destroy_token(self, token: str, user: UP) -> None:
        """Do nothing because API-key revocation is handled by API-key management flows."""

    async def _read_signed_request(
        self,
        user_manager: UserManagerProtocol[UP, ID],
    ) -> ApiKeyAuthenticationAttempt[UP]:
        signed_request = get_current_signed_api_key_request()
        if signed_request is None:
            return _api_key_failure(ApiKeyFailureReason.SIGNATURE_INVALID)
        api_key, row_failure = await self._get_signed_api_key_for_failure_classification(signed_request.key_id)
        if row_failure is not None or api_key is None:
            return _api_key_failure(row_failure or ApiKeyFailureReason.SIGNATURE_INVALID)
        if self._signed_request_has_skew(signed_request):
            return _api_key_failure(ApiKeyFailureReason.SIGNATURE_TIMESTAMP_SKEW)
        secret = self._decrypt_signing_secret(api_key)
        if secret is None:
            return _api_key_failure(ApiKeyFailureReason.SIGNATURE_INVALID)
        if not self._signed_request_signature_matches(signed_request, secret=secret):
            return _api_key_failure(ApiKeyFailureReason.SIGNATURE_INVALID)
        return await self._signed_authentication_result(user_manager, api_key, signed_request)

    async def _signed_authentication_result(
        self,
        user_manager: UserManagerProtocol[UP, ID],
        api_key: _ApiKeyRow[ID],
        signed_request: SignedApiKeyRequest,
    ) -> ApiKeyAuthenticationAttempt[UP]:
        """Return the signed API-key authentication result after user and nonce checks."""
        user = await user_manager.get(api_key.user_id)
        if user is None:
            return _api_key_failure(ApiKeyFailureReason.SIGNATURE_INVALID)
        nonce_failure = await self._consume_signed_nonce(api_key, signed_request)
        if nonce_failure is not None:
            return _api_key_failure(nonce_failure)
        return _api_key_success(self._api_key_authentication_result(user, api_key))

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

    async def _consume_signed_nonce(
        self,
        api_key: _ApiKeyRow[ID],
        signed_request: SignedApiKeyRequest,
    ) -> ApiKeyFailureReason | None:
        """Return the signed nonce failure reason, if the nonce was rejected."""
        nonce_store = self.nonce_store
        if nonce_store is None:
            return ApiKeyFailureReason.SIGNATURE_INVALID
        return await self._mark_signed_nonce_used(
            nonce_store,
            key_id=api_key.key_id,
            nonce=signed_request.nonce,
        )

    def _api_key_authentication_result(self, user: UP, api_key: _ApiKeyRow[ID]) -> ApiKeyAuthenticationResult[UP]:
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

    async def _mark_signed_nonce_used(
        self,
        nonce_store: ApiKeyNonceStore,
        *,
        key_id: str,
        nonce: str,
    ) -> ApiKeyFailureReason | None:
        nonce_result = await nonce_store.mark_used(
            key_id=key_id,
            nonce=nonce,
            ttl_seconds=max(self.signing_skew_seconds * 2, 1),
        )
        if nonce_result.stored:
            return None
        if nonce_result.rejected_as_replay:
            return ApiKeyFailureReason.SIGNATURE_NONCE_REPLAY
        return ApiKeyFailureReason.SIGNATURE_INVALID

    def _decrypt_signing_secret(self, api_key: _ApiKeyRow[ID]) -> str | None:
        encrypted_secret = getattr(api_key, "encrypted_secret", None)
        if encrypted_secret is None or self.secret_encryption_keyring is None:
            return None
        try:
            return self.secret_encryption_keyring.decrypt(encrypted_secret.decode("utf-8"))
        except (SecretAtRestError, UnicodeDecodeError):
            return None

    async def classify_failure_reason(self, token: str | None) -> ApiKeyFailureReason:
        """Return the most specific API-key authentication failure reason for ``token``."""
        if token == API_KEY_HMAC_SCHEME:
            return await self._classify_signed_failure_reason()
        return await self._classify_bearer_failure_reason(token)

    async def classify_failure_code(self, token: str | None) -> ErrorCode:
        """Return the most specific API-key authentication failure code for ``token``."""
        return api_key_failure_reason_to_error_code(await self.classify_failure_reason(token))

    async def _classify_bearer_failure_reason(self, token: str | None) -> ApiKeyFailureReason:  # noqa: PLR0911
        """Return the bearer API-key failure reason without resolving the owning user."""
        if token is None:
            return ApiKeyFailureReason.INVALID
        parsed = parse_api_key(token, expected_prefix_env=self.prefix_env, prefix=self.prefix)
        if parsed is None:
            return ApiKeyFailureReason.INVALID
        api_key = await self._lookup_api_key(parsed.key_id)
        if api_key is None or api_key.prefix_env != parsed.prefix_env:
            return ApiKeyFailureReason.INVALID
        if getattr(api_key, "signing_required", False):
            return ApiKeyFailureReason.SIGNATURE_INVALID
        row_failure = self._classify_bearer_api_key_row(api_key)
        if row_failure is not None:
            return row_failure
        if not api_key_secret_matches(
            stored_digest=api_key.hashed_secret,
            api_key_hash_secret=self._api_key_hash_secret,
            secret=parsed.secret,
        ):
            return ApiKeyFailureReason.INVALID
        return ApiKeyFailureReason.INVALID

    async def _classify_signed_failure_reason(self) -> ApiKeyFailureReason:
        signed_request = get_current_signed_api_key_request()
        if signed_request is None:
            return ApiKeyFailureReason.SIGNATURE_INVALID
        api_key, row_failure_code = await self._get_signed_api_key_for_failure_classification(signed_request.key_id)
        if row_failure_code is not None or api_key is None:
            return row_failure_code or ApiKeyFailureReason.SIGNATURE_INVALID
        if self._signed_request_has_skew(signed_request):
            return ApiKeyFailureReason.SIGNATURE_TIMESTAMP_SKEW
        secret = self._decrypt_signing_secret(api_key)
        if secret is None or not self._signed_request_signature_matches(signed_request, secret=secret):
            return ApiKeyFailureReason.SIGNATURE_INVALID
        return ApiKeyFailureReason.SIGNATURE_INVALID

    async def _get_signed_api_key_for_failure_classification(
        self,
        key_id: str,
    ) -> tuple[_ApiKeyRow[ID] | None, ApiKeyFailureReason | None]:
        """Return a signed API-key row plus any row-state failure code."""
        api_key = await self._lookup_api_key(key_id)
        if api_key is None:
            return None, ApiKeyFailureReason.SIGNATURE_INVALID
        return api_key, self._classify_signed_api_key_row(api_key)

    async def _lookup_api_key(self, key_id: str) -> _ApiKeyRow[ID] | None:
        """Return an API-key row when the store result matches the strategy contract."""
        api_key = await self.api_key_store.get_by_key_id(key_id, include_inactive=True)
        if isinstance(api_key, _ApiKeyRow):
            return api_key
        return None

    @staticmethod
    def _classify_bearer_api_key_row(api_key: _ApiKeyRow[Any]) -> ApiKeyFailureReason | None:
        """Return a failure reason for bearer API-key row state, if the row is unusable."""
        if api_key.revoked_at is not None:
            return ApiKeyFailureReason.REVOKED
        if _expires_in_past(api_key.expires_at):
            return ApiKeyFailureReason.EXPIRED
        return None

    def _classify_signed_api_key_row(self, api_key: _ApiKeyRow[ID]) -> ApiKeyFailureReason | None:
        """Return a failure code for signed API-key row state, if the row is unusable."""
        if self.prefix_env is not None and api_key.prefix_env != self.prefix_env:
            return ApiKeyFailureReason.SIGNATURE_INVALID
        if api_key.revoked_at is not None:
            return ApiKeyFailureReason.REVOKED
        if _expires_in_past(api_key.expires_at):
            return ApiKeyFailureReason.EXPIRED
        if not getattr(api_key, "signing_required", False):
            return ApiKeyFailureReason.SIGNATURE_INVALID
        return None


def _api_key_success[UP: UserProtocol[Any]](
    result: ApiKeyAuthenticationResult[UP],
) -> ApiKeyAuthenticationAttempt[UP]:
    return ApiKeyAuthenticationAttempt(result=result, failure_reason=None)


def _api_key_failure[UP: UserProtocol[Any]](reason: ApiKeyFailureReason) -> ApiKeyAuthenticationAttempt[UP]:
    return ApiKeyAuthenticationAttempt(result=None, failure_reason=reason)


def api_key_failure_reason_to_error_code(reason: ApiKeyFailureReason) -> ErrorCode:
    """Map internal API-key failure reasons to stable public error codes.

    Returns:
        Stable public error code emitted in API-key authentication failure responses.
    """
    return _API_KEY_FAILURE_ERROR_CODES[reason]


_API_KEY_FAILURE_ERROR_CODES: dict[ApiKeyFailureReason, ErrorCode] = {
    ApiKeyFailureReason.INVALID: ErrorCode.API_KEY_INVALID,
    ApiKeyFailureReason.REVOKED: ErrorCode.API_KEY_REVOKED,
    ApiKeyFailureReason.EXPIRED: ErrorCode.API_KEY_EXPIRED,
    ApiKeyFailureReason.SIGNATURE_INVALID: ErrorCode.API_KEY_SIGNATURE_INVALID,
    ApiKeyFailureReason.SIGNATURE_TIMESTAMP_SKEW: ErrorCode.API_KEY_SIGNATURE_TIMESTAMP_SKEW,
    ApiKeyFailureReason.SIGNATURE_NONCE_REPLAY: ErrorCode.API_KEY_SIGNATURE_NONCE_REPLAY,
}


def _expires_in_past(expires_at: datetime | None) -> bool:
    if expires_at is None:
        return False
    aware_expires_at = expires_at.replace(tzinfo=UTC) if expires_at.tzinfo is None else expires_at.astimezone(UTC)
    return aware_expires_at <= datetime.now(tz=UTC)
