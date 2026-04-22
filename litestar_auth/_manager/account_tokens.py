"""Internal account-token services for ``BaseUserManager``."""
# ruff: noqa: ANN401, DOC201, DOC501, SLF001

from __future__ import annotations

import hashlib
import hmac
import secrets
from datetime import UTC, datetime, timedelta
from typing import TYPE_CHECKING, Any, Protocol, cast

import jwt

from litestar_auth._manager._coercions import _managed_user
from litestar_auth._manager._protocols import PasswordManagedUserManagerProtocol, UserManagerHooksProtocol
from litestar_auth.exceptions import InvalidResetPasswordTokenError, InvalidVerifyTokenError, UserNotExistsError

if TYPE_CHECKING:
    from litestar_auth._manager.construction import AccountTokenSecrets

type _InvalidTokenError = type[InvalidVerifyTokenError | InvalidResetPasswordTokenError]


class _AccountTokenSecurityManagerProtocol[ID](Protocol):
    """Manager surface required by token security operations."""

    account_token_secrets: AccountTokenSecrets
    id_parser: Any


class _AccountTokensManagerProtocol[UP, ID](
    PasswordManagedUserManagerProtocol[UP],
    _AccountTokenSecurityManagerProtocol[ID],
    UserManagerHooksProtocol[UP],
    Protocol,
):
    """Manager surface required by verify/reset token flows."""

    verification_token_lifetime: timedelta
    reset_password_token_lifetime: timedelta

    async def _invalidate_all_tokens(self, user: UP) -> None: ...  # pragma: no cover


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

    def password_fingerprint(self, hashed_password: str) -> str:
        """Compute the password fingerprint used by reset-password tokens."""
        return hmac.new(
            self._manager.account_token_secrets.reset_password_token_secret.get_secret_value().encode(),
            hashed_password.encode(),
            hashlib.sha256,
        ).hexdigest()

    def write_token(
        self,
        *,
        subject: str,
        secret: str,
        audience: str,
        lifetime: timedelta,
        extra_claims: dict[str, Any] | None = None,
    ) -> str:
        """Sign a short-lived JWT bound to an arbitrary subject string."""
        return self.write_token_subject(
            subject=subject,
            secret=secret,
            audience=audience,
            lifetime=lifetime,
            extra_claims=extra_claims,
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
        issued_at = datetime.now(tz=UTC)
        payload: dict[str, Any] = {
            "sub": subject,
            "aud": audience,
            "iat": issued_at,
            "nbf": issued_at,
            "exp": issued_at + lifetime,
            "jti": secrets.token_hex(16),
        }
        if extra_claims:
            payload.update(extra_claims)
        return jwt.encode(payload, secret, algorithm="HS256")

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
            payload = jwt.decode(
                token,
                secret,
                algorithms=["HS256"],
                audience=audience,
                options={"require": ["exp", "aud", "iat", "nbf", "jti", "sub"]},
            )
        except (jwt.ExpiredSignatureError, jwt.InvalidTokenError) as exc:
            self._logger.warning("Manager token validation failed", extra={"event": "token_validation_failed"})
            raise invalid_token_error from exc

        return payload

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

    async def get_user_from_token(
        self,
        token: str,
        *,
        user_db: Any,
        secret: str,
        audience: str,
        invalid_token_error: _InvalidTokenError,
    ) -> UP:
        """Resolve a user from a signed manager token."""
        user_id = self.read_token_subject(
            token,
            secret=secret,
            audience=audience,
            invalid_token_error=invalid_token_error,
        )
        user = await user_db.get(user_id)
        if user is None:
            raise UserNotExistsError
        return user

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
        verify_token_audience: str,
        reset_password_token_audience: str,
        token_security: AccountTokenSecurityService[UP, ID],
        logger: Any,
    ) -> None:
        """Bind service dependencies."""
        self._manager = manager
        self._verify_token_audience = verify_token_audience
        self._reset_password_token_audience = reset_password_token_audience
        self._token_security = token_security
        self._logger = logger

    @property
    def security(self) -> AccountTokenSecurityService[UP, ID]:
        """Return the low-level JWT and fingerprint helper surface."""
        return self._token_security

    async def verify(self, token: str) -> UP:
        """Mark the token subject as verified."""
        user = await self._token_security.get_user_from_token(
            token,
            user_db=self._manager.user_db,
            secret=self._manager.account_token_secrets.verification_token_secret.get_secret_value(),
            audience=self._verify_token_audience,
            invalid_token_error=InvalidVerifyTokenError,
        )
        managed_user = _managed_user(user)
        if managed_user.is_verified:
            msg = "The user is already verified."
            raise InvalidVerifyTokenError(msg)

        updated_user = await self._manager.user_db.update(user, {"is_verified": True})
        await self._manager.on_after_verify(updated_user)
        return updated_user

    async def request_verify_token(self, email: str) -> None:
        """Generate a verification token without exposing account state."""
        normalized_email = self._manager._normalize_email(email)
        user = await self._manager.user_db.get_by_email(normalized_email)
        deliverable = user is not None and not _managed_user(user).is_verified
        token = (
            self.write_verify_token(user)
            if deliverable
            else self._token_security.write_token(
                subject="verification-placeholder",
                secret=self._manager.account_token_secrets.verification_token_secret.get_secret_value(),
                audience=self._verify_token_audience,
                lifetime=self._manager.verification_token_lifetime,
            )
        )

        await self._manager.on_after_request_verify_token(
            user if deliverable else None,
            token if deliverable else None,
        )

    async def forgot_password(self, email: str, *, dummy_hash: str) -> None:
        """Generate a reset token without exposing user existence."""
        email = self._manager._normalize_email(email)
        user = await self._manager.user_db.get_by_email(email)
        token = self.write_reset_password_token(user, dummy_hash=dummy_hash)

        await self._manager.on_after_forgot_password(
            user,
            token if user is not None else None,
        )

    async def reset_password(self, token: str, password: str) -> UP:
        """Reset the subject user's password."""
        user, payload = await self._token_security.get_reset_password_context(token, user_db=self._manager.user_db)

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

        self._manager._validate_password(password)
        update_dict = {"hashed_password": self._manager.password_helper.hash(password)}
        updated_user = await self._manager.user_db.update(user, update_dict)
        await self._manager._invalidate_all_tokens(updated_user)
        await self._manager.on_after_reset_password(updated_user)
        return updated_user

    def write_verify_token(self, user: UP) -> str:
        """Sign a verification token for a user."""
        return self.write_user_token(
            user,
            secret=self._manager.account_token_secrets.verification_token_secret.get_secret_value(),
            audience=self._verify_token_audience,
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
        extra_claims = {"password_fingerprint": self.password_fingerprint(fingerprint_source)}

        return self._token_security.write_token(
            subject=subject,
            secret=self._manager.account_token_secrets.reset_password_token_secret.get_secret_value(),
            audience=self._reset_password_token_audience,
            lifetime=self._manager.reset_password_token_lifetime,
            extra_claims=extra_claims,
        )

    def password_fingerprint(self, hashed_password: str) -> str:
        """Compute the password fingerprint for reset tokens."""
        return self._token_security.password_fingerprint(hashed_password)

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
        token_claims = dict(extra_claims or {})
        if audience == self._reset_password_token_audience and "password_fingerprint" not in token_claims:
            token_claims["password_fingerprint"] = self.password_fingerprint(
                _managed_user(user).hashed_password,
            )

        return self._token_security.write_token(
            subject=str(_managed_user(user).id),
            secret=secret,
            audience=audience,
            lifetime=lifetime,
            extra_claims=token_claims or None,
        )
