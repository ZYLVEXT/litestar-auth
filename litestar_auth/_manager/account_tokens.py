"""Internal account-token services for ``BaseUserManager``."""
# ruff: noqa: ANN401, DOC201, DOC501, SLF001

from __future__ import annotations

import hashlib
import hmac
import secrets
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from typing import TYPE_CHECKING, Any, Protocol, cast

import jwt

from litestar_auth._jwt_headers import JwtDecodeConfig, decode_signed_jwt, jwt_encode_headers
from litestar_auth._manager._coercions import _managed_user
from litestar_auth._manager._protocols import UserDatabaseManagerProtocol
from litestar_auth.authentication.strategy._jwt_denylist import denylist_ttl_seconds
from litestar_auth.exceptions import (
    ConfigurationError,
    ExpiredOrganizationInvitationTokenError,
    InvalidOrganizationInvitationTokenError,
    InvalidResetPasswordTokenError,
    InvalidVerifyTokenError,
    UserNotExistsError,
)

if TYPE_CHECKING:
    from collections.abc import Callable, Mapping

    from litestar_auth._manager.construction import AccountTokenSecrets
    from litestar_auth._manager.hooks import ManagerHookBus
    from litestar_auth._manager.user_policy import UserPolicy
    from litestar_auth.authentication.strategy._jwt_denylist import JWTDenylistStore

type _InvalidTokenError = type[
    InvalidVerifyTokenError | InvalidResetPasswordTokenError | InvalidOrganizationInvitationTokenError
]


class OrganizationInvitationLookupStore[INVITATION](Protocol):
    """Store surface required for invitation-token validation."""

    async def get_invitation_by_token_hash(self, token_hash: bytes) -> INVITATION | None:
        """Return an invitation row by persisted token digest when present."""


@dataclass(frozen=True, slots=True)
class AccountTokenAudiences:
    """JWT audiences used by account verification and reset-password tokens."""

    verify: str
    reset_password: str
    organization_invitation: str


@dataclass(frozen=True, slots=True)
class TokenWriteRequest:
    """Input for signing account-scoped manager tokens."""

    subject: str
    audience: str
    secret: str
    lifetime: timedelta
    extra_claims: Mapping[str, Any] | None = None
    issued_at: datetime | None = None


@dataclass(frozen=True, slots=True)
class OrganizationInvitationToken:
    """Signed invitation token plus the digest stored on the invitation row."""

    token: str
    token_hash: bytes
    expires_at: datetime


@dataclass(frozen=True, slots=True)
class AccountTokensServiceDependencies[UP, ID]:
    """Dependencies required by account-token flow orchestration."""

    audiences: AccountTokenAudiences
    hook_bus: ManagerHookBus[UP]
    token_security: AccountTokenSecurityService[UP, ID]
    logger: Any
    policy: UserPolicy
    account_token_denylist_store: JWTDenylistStore | None = None


class TokenWriter:
    """Canonical account-token writer with reset-password fingerprint handling."""

    def __init__(
        self,
        *,
        reset_password_audience: str,
        password_fingerprint: Callable[[str], str],
    ) -> None:
        """Bind reset-password token policy."""
        self._reset_password_audience = reset_password_audience
        self._password_fingerprint = password_fingerprint

    def write(
        self,
        request: TokenWriteRequest,
        *,
        password_fingerprint_source: str | None = None,
    ) -> str:
        """Sign an account token after applying account-token claim policy."""
        return self.write_token_subject(
            TokenWriteRequest(
                subject=request.subject,
                secret=request.secret,
                audience=request.audience,
                lifetime=request.lifetime,
                issued_at=request.issued_at,
                extra_claims=self._extra_claims_for_request(
                    request,
                    password_fingerprint_source=password_fingerprint_source,
                ),
            ),
        )

    def _extra_claims_for_request(
        self,
        request: TokenWriteRequest,
        *,
        password_fingerprint_source: str | None,
    ) -> dict[str, Any] | None:
        """Return extra claims with reset-password fingerprint policy applied."""
        token_claims = dict(request.extra_claims or {})
        if request.audience != self._reset_password_audience:
            token_claims.pop("password_fingerprint", None)
            return token_claims or None

        if "password_fingerprint" not in token_claims:
            if password_fingerprint_source is None:
                msg = "reset-password tokens require a password fingerprint source"
                raise ValueError(msg)
            token_claims["password_fingerprint"] = self._password_fingerprint(password_fingerprint_source)
        return token_claims

    @staticmethod
    def write_token_subject(request: TokenWriteRequest) -> str:
        """Sign a short-lived JWT bound to an arbitrary subject string."""
        issued_at = request.issued_at or datetime.now(tz=UTC)
        payload: dict[str, Any] = {
            "sub": request.subject,
            "aud": request.audience,
            "iat": issued_at,
            "nbf": issued_at,
            "exp": issued_at + request.lifetime,
            "jti": secrets.token_hex(16),
        }
        if request.extra_claims:
            payload.update(request.extra_claims)
        return jwt.encode(payload, request.secret, algorithm="HS256", headers=jwt_encode_headers())


class _AccountTokenSecurityManagerProtocol[ID](Protocol):
    """Manager surface required by token security operations."""

    account_token_secrets: AccountTokenSecrets
    id_parser: Any


class _AccountTokensManagerProtocol[UP, ID](
    UserDatabaseManagerProtocol[UP],
    _AccountTokenSecurityManagerProtocol[ID],
    Protocol,
):
    """Manager surface required by verify/reset token flows."""

    verification_token_lifetime: timedelta
    reset_password_token_lifetime: timedelta
    organization_invitation_token_lifetime: timedelta

    async def _invalidate_all_tokens(self, user: UP) -> None:
        pass


class AccountTokenSecurityService[UP, ID]:
    """Handle JWT encoding/decoding and password-fingerprint concerns."""

    def __init__(
        self,
        manager: _AccountTokenSecurityManagerProtocol[ID],
        *,
        logger: Any,
        reset_password_token_audience: str,
    ) -> None:
        """Bind manager-provided token security dependencies."""
        self._manager = manager
        self._logger = logger
        self._reset_password_token_audience = reset_password_token_audience
        self._token_writer = TokenWriter(
            reset_password_audience=reset_password_token_audience,
            password_fingerprint=self.password_fingerprint,
        )

    @property
    def token_writer(self) -> TokenWriter:
        """Return the canonical account-token writer."""
        return self._token_writer

    def password_fingerprint(self, hashed_password: str) -> str:
        """Compute the password fingerprint used by reset-password tokens."""
        return hmac.new(
            self._manager.account_token_secrets.reset_password_token_secret.get_secret_value().encode(),
            hashed_password.encode(),
            hashlib.sha256,
        ).hexdigest()

    def organization_invitation_token_hash(self, token: str) -> bytes:
        """Return the keyed digest persisted for organization invitation lookup."""
        return hmac.digest(
            self._organization_invitation_token_secret().encode(),
            token.encode(),
            hashlib.sha256,
        )

    def _organization_invitation_token_secret(self) -> str:
        """Return the configured organization-invitation token secret."""
        secret = self._manager.account_token_secrets.organization_invitation_token_secret
        if secret is not None:
            return secret.get_secret_value()
        msg = "organization_invitation_token_secret is required to issue or validate organization invitation tokens."
        raise ConfigurationError(msg)

    @staticmethod
    def write_token(
        *,
        subject: str,
        secret: str,
        audience: str,
        lifetime: timedelta,
        extra_claims: dict[str, Any] | None = None,
    ) -> str:
        """Sign a short-lived JWT bound to an arbitrary subject string."""
        return TokenWriter.write_token_subject(
            TokenWriteRequest(
                subject=subject,
                secret=secret,
                audience=audience,
                lifetime=lifetime,
                extra_claims=extra_claims,
            ),
        )

    @staticmethod
    def write_token_subject(
        *,
        subject: str,
        secret: str,
        audience: str,
        lifetime: timedelta,
        extra_claims: dict[str, Any] | None = None,
    ) -> str:
        """Sign a short-lived JWT bound to an arbitrary subject string."""
        return TokenWriter.write_token_subject(
            TokenWriteRequest(
                subject=subject,
                secret=secret,
                audience=audience,
                lifetime=lifetime,
                extra_claims=extra_claims,
            ),
        )

    def decode_token(
        self,
        token: str,
        *,
        secret: str,
        audience: str,
        invalid_token_error: _InvalidTokenError,
    ) -> dict[str, Any]:
        """Decode and validate a manager token payload."""
        try:
            payload = decode_signed_jwt(
                token,
                config=JwtDecodeConfig(
                    key=secret,
                    algorithms=["HS256"],
                    audience=audience,
                    options={"require": ["exp", "aud", "iat", "nbf", "jti", "sub"]},
                ),
            )
        except (jwt.ExpiredSignatureError, jwt.InvalidTokenError) as exc:
            self._logger.warning("Manager token validation failed", extra={"event": "token_validation_failed"})
            raise invalid_token_error from exc

        return payload

    def decode_organization_invitation_token(self, token: str, *, audience: str) -> dict[str, Any]:
        """Decode an organization invitation token with expired-token classification."""
        try:
            return decode_signed_jwt(
                token,
                config=JwtDecodeConfig(
                    key=self._organization_invitation_token_secret(),
                    algorithms=["HS256"],
                    audience=audience,
                    options={"require": ["exp", "aud", "iat", "nbf", "jti", "sub"]},
                ),
            )
        except jwt.ExpiredSignatureError as exc:
            self._logger.warning("Manager token validation failed", extra={"event": "token_validation_failed"})
            raise ExpiredOrganizationInvitationTokenError from exc
        except jwt.InvalidTokenError as exc:
            self._logger.warning("Manager token validation failed", extra={"event": "token_validation_failed"})
            raise InvalidOrganizationInvitationTokenError from exc

    def _subject_id_from_payload(
        self,
        payload: dict[str, Any],
        invalid_token_error: _InvalidTokenError,
    ) -> ID:
        """Extract and parse ``sub`` from an already-decoded manager token payload."""
        subject = payload.get("sub")
        if not isinstance(subject, str) or not subject:
            self._logger.warning("Manager token subject validation failed", extra={"event": "token_validation_failed"})
            raise invalid_token_error

        try:
            return self._manager.id_parser(subject) if self._manager.id_parser is not None else cast("ID", subject)
        except ValueError as exc:
            self._logger.warning("Manager token subject parsing failed", extra={"event": "token_validation_failed"})
            raise invalid_token_error from exc

    def read_token_subject(
        self,
        token: str,
        *,
        secret: str,
        audience: str,
        invalid_token_error: _InvalidTokenError,
    ) -> ID:
        """Decode and validate a manager token subject."""
        payload = self.decode_token(token, secret=secret, audience=audience, invalid_token_error=invalid_token_error)
        return self._subject_id_from_payload(payload, invalid_token_error)

    async def get_user_and_payload_from_token(
        self,
        token: str,
        *,
        user_db: Any,
        secret: str,
        audience: str,
        invalid_token_error: _InvalidTokenError,
    ) -> tuple[UP, dict[str, Any]]:
        """Resolve a user plus the validated JWT payload from a signed manager token."""
        payload = self.decode_token(token, secret=secret, audience=audience, invalid_token_error=invalid_token_error)
        user_id = self._subject_id_from_payload(payload, invalid_token_error)
        user = await user_db.get(user_id)
        if user is None:
            raise UserNotExistsError
        return user, payload

    async def get_reset_password_context(
        self,
        token: str,
        *,
        user_db: Any,
    ) -> tuple[UP, dict[str, Any]]:
        """Resolve the reset-password user plus the validated JWT payload."""
        payload = self.decode_token(
            token,
            secret=self._manager.account_token_secrets.reset_password_token_secret.get_secret_value(),
            audience=self._reset_password_token_audience,
            invalid_token_error=InvalidResetPasswordTokenError,
        )
        user_id = self._subject_id_from_payload(payload, InvalidResetPasswordTokenError)
        try:
            user = await user_db.get(user_id)
        except Exception as exc:  # pragma: no cover - defensive lookup path across custom backends
            self._logger.warning(
                "User lookup failed during reset-password",
                extra={"event": "token_validation_failed"},
                exc_info=exc,
            )
            raise InvalidResetPasswordTokenError from exc

        if user is None:
            self._logger.warning(
                "Reset-password token referenced missing user",
                extra={"event": "token_validation_failed"},
            )
            raise InvalidResetPasswordTokenError

        return user, payload


class AccountTokensService[UP, ID]:
    """Handle verify and reset token flows for the manager facade."""

    def __init__(
        self,
        manager: _AccountTokensManagerProtocol[UP, ID],
        *,
        dependencies: AccountTokensServiceDependencies[UP, ID],
    ) -> None:
        """Bind service dependencies."""
        self._manager = manager
        self._audiences = dependencies.audiences
        self._hook_bus = dependencies.hook_bus
        self._token_security = dependencies.token_security
        self._logger = dependencies.logger
        self._policy = dependencies.policy
        self._denylist_store = dependencies.account_token_denylist_store

    async def _reject_if_token_replayed(self, payload: dict[str, Any], invalid_token_error: _InvalidTokenError) -> None:
        """Reject a verify/reset token whose ``jti`` was already consumed.

        No-op when no denylist store is configured (the default), in which case
        account tokens stay single-use only through password/verification-state rotation.
        ``jti`` is guaranteed present and string-typed here: it is a required claim and
        PyJWT raises ``InvalidJTIError`` for non-string values during decode.
        """
        store = self._denylist_store
        if store is None:
            return
        if await store.is_denied(payload["jti"]):
            self._logger.warning("Account token replay rejected", extra={"event": "token_validation_failed"})
            raise invalid_token_error

    async def _consume_token(self, payload: dict[str, Any]) -> None:
        """Record a verify/reset token's ``jti`` as spent until its original expiry."""
        store = self._denylist_store
        if store is None:
            return
        await store.deny(payload["jti"], ttl_seconds=denylist_ttl_seconds(payload.get("exp")))

    @property
    def security(self) -> AccountTokenSecurityService[UP, ID]:
        """Return the low-level JWT and fingerprint helper surface."""
        return self._token_security

    def _write_token(
        self,
        request: TokenWriteRequest,
        *,
        password_fingerprint_source: str | None = None,
    ) -> str:
        """Write an account token through the canonical token writer."""
        return self._token_security.token_writer.write(
            request,
            password_fingerprint_source=password_fingerprint_source,
        )

    async def verify(self, token: str) -> UP:
        """Mark the token subject as verified."""
        user, payload = await self._token_security.get_user_and_payload_from_token(
            token,
            user_db=self._manager.user_db,
            secret=self._manager.account_token_secrets.verification_token_secret.get_secret_value(),
            audience=self._audiences.verify,
            invalid_token_error=InvalidVerifyTokenError,
        )
        await self._reject_if_token_replayed(payload, InvalidVerifyTokenError)
        managed_user = _managed_user(user)
        if managed_user.is_verified:
            msg = "The user is already verified."
            raise InvalidVerifyTokenError(msg)

        updated_user = await self._manager.user_db.update(user, {"is_verified": True})
        await self._consume_token(payload)
        await self._hook_bus.fire("after_verify", updated_user)
        return updated_user

    async def request_verify_token(self, email: str) -> None:
        """Generate a verification token without exposing account state."""
        normalized_email = self._policy.normalize_email(email)
        user = await self._manager.user_db.get_by_email(normalized_email)
        deliverable = user is not None and not _managed_user(user).is_verified
        token = (
            self.write_verify_token(user)
            if deliverable
            else self._write_token(
                TokenWriteRequest(
                    subject="verification-placeholder",
                    secret=self._manager.account_token_secrets.verification_token_secret.get_secret_value(),
                    audience=self._audiences.verify,
                    lifetime=self._manager.verification_token_lifetime,
                ),
            )
        )

        await self._hook_bus.fire(
            "after_request_verify_token",
            user if deliverable else None,
            token if deliverable else None,
        )

    async def forgot_password(self, email: str, *, dummy_hash: str) -> None:
        """Generate a reset token without exposing user existence."""
        email = self._policy.normalize_email(email)
        user = await self._manager.user_db.get_by_email(email)
        token = self.write_reset_password_token(user, dummy_hash=dummy_hash)

        await self._hook_bus.fire(
            "after_forgot_password",
            user,
            token if user is not None else None,
        )

    async def reset_password(self, token: str, password: str) -> UP:
        """Reset the subject user's password."""
        user, payload = await self._token_security.get_reset_password_context(token, user_db=self._manager.user_db)
        await self._reject_if_token_replayed(payload, InvalidResetPasswordTokenError)

        # Security: reject password resets for deactivated accounts
        managed = _managed_user(user)
        if not managed.is_active:
            self._logger.warning(
                "Password reset rejected for inactive account",
                extra={"event": "reset_password_inactive_account"},
            )
            raise InvalidResetPasswordTokenError

        token_fingerprint = payload.get("password_fingerprint")
        if not isinstance(token_fingerprint, str):
            self._logger.warning(
                "Reset token missing password fingerprint",
                extra={"event": "token_validation_failed"},
            )
            raise InvalidResetPasswordTokenError

        current_fingerprint = self.password_fingerprint(_managed_user(user).hashed_password)
        if not hmac.compare_digest(token_fingerprint, current_fingerprint):
            self._logger.warning(
                "Reset token fingerprint mismatch (password changed)",
                extra={"event": "token_validation_failed"},
            )
            raise InvalidResetPasswordTokenError

        self._policy.validate_password(password)
        update_dict = {"hashed_password": self._policy.password_helper.hash(password)}
        updated_user = await self._manager.user_db.update(user, update_dict)
        await self._manager._invalidate_all_tokens(updated_user)
        await self._consume_token(payload)
        await self._hook_bus.fire("after_reset_password", updated_user)
        return updated_user

    def write_verify_token(self, user: UP) -> str:
        """Sign a verification token for a user."""
        return self.write_user_token(
            user,
            secret=self._manager.account_token_secrets.verification_token_secret.get_secret_value(),
            audience=self._audiences.verify,
            lifetime=self._manager.verification_token_lifetime,
        )

    def write_reset_password_token(self, user: UP | None, *, dummy_hash: str) -> str:
        """Sign a reset-password token for a real or dummy subject."""
        subject = ""
        fingerprint_source = dummy_hash
        if user is not None:
            managed_user = _managed_user(user)
            subject = str(managed_user.id)
            fingerprint_source = managed_user.hashed_password

        return self._write_token(
            TokenWriteRequest(
                subject=subject,
                secret=self._manager.account_token_secrets.reset_password_token_secret.get_secret_value(),
                audience=self._audiences.reset_password,
                lifetime=self._manager.reset_password_token_lifetime,
            ),
            password_fingerprint_source=fingerprint_source,
        )

    def password_fingerprint(self, hashed_password: str) -> str:
        """Compute the password fingerprint for reset tokens."""
        return self._token_security.password_fingerprint(hashed_password)

    def write_organization_invitation_token(self, *, issued_at: datetime | None = None) -> OrganizationInvitationToken:
        """Sign an organization invitation token and return its persistence digest."""
        resolved_issued_at = issued_at or datetime.now(tz=UTC)
        lifetime = self._manager.organization_invitation_token_lifetime
        token = self._write_token(
            TokenWriteRequest(
                subject=secrets.token_urlsafe(32),
                secret=self._token_security._organization_invitation_token_secret(),
                audience=self._audiences.organization_invitation,
                lifetime=lifetime,
                issued_at=resolved_issued_at,
            ),
        )
        return OrganizationInvitationToken(
            token=token,
            token_hash=self.organization_invitation_token_hash(token),
            expires_at=resolved_issued_at + lifetime,
        )

    def organization_invitation_token_hash(self, token: str) -> bytes:
        """Return the keyed digest persisted for organization invitation lookup."""
        return self._token_security.organization_invitation_token_hash(token)

    async def validate_organization_invitation_token[INVITATION](
        self,
        token: str,
        *,
        organization_store: OrganizationInvitationLookupStore[INVITATION],
        now: datetime | None = None,
    ) -> INVITATION:
        """Return the pending invitation row for a valid signed invitation token."""
        payload = self._token_security.decode_organization_invitation_token(
            token,
            audience=self._audiences.organization_invitation,
        )
        subject = payload.get("sub")
        if not isinstance(subject, str) or not subject:
            self._logger.warning("Manager token subject validation failed", extra={"event": "token_validation_failed"})
            raise InvalidOrganizationInvitationTokenError

        invitation = await organization_store.get_invitation_by_token_hash(
            self.organization_invitation_token_hash(token),
        )
        if invitation is None:
            self._logger.warning(
                "Organization invitation token referenced missing invitation",
                extra={"event": "token_validation_failed"},
            )
            raise InvalidOrganizationInvitationTokenError

        self._validate_organization_invitation_row(invitation, now=now or datetime.now(tz=UTC))
        return invitation

    def _validate_organization_invitation_row(self, invitation: object, *, now: datetime) -> None:
        """Reject invitation rows that are not pending and unexpired."""
        if getattr(invitation, "status", None) != "pending":
            self._logger.warning(
                "Organization invitation token referenced non-pending invitation",
                extra={"event": "token_validation_failed"},
            )
            raise InvalidOrganizationInvitationTokenError

        expires_at = getattr(invitation, "expires_at", None)
        comparison_now = now
        if isinstance(expires_at, datetime) and expires_at.tzinfo is None:
            comparison_now = now.replace(tzinfo=None)
        if not isinstance(expires_at, datetime) or expires_at <= comparison_now:
            self._logger.warning(
                "Organization invitation token referenced expired invitation",
                extra={"event": "token_validation_failed"},
            )
            raise ExpiredOrganizationInvitationTokenError

    def write_user_token(
        self,
        user: UP,
        *,
        secret: str,
        audience: str,
        lifetime: timedelta,
        extra_claims: dict[str, Any] | None = None,
    ) -> str:
        """Sign a short-lived JWT for a user."""
        managed_user = _managed_user(user)
        return self._write_token(
            TokenWriteRequest(
                subject=str(managed_user.id),
                secret=secret,
                audience=audience,
                lifetime=lifetime,
                extra_claims=extra_claims,
            ),
            password_fingerprint_source=managed_user.hashed_password,
        )
