"""Password hashing helpers built on top of pwdlib."""

from __future__ import annotations

from typing import Self

from pwdlib import PasswordHash
from pwdlib.exceptions import UnknownHashError
from pwdlib.hashers.argon2 import Argon2Hasher


def _build_default_password_hash() -> PasswordHash:
    """Return the library's default password-hashing pipeline."""
    return PasswordHash((Argon2Hasher(),))


class PasswordHelper:
    """Hash and verify passwords with a configurable pwdlib pipeline."""

    @classmethod
    def from_defaults(cls) -> Self:
        """Return a helper configured with the library's default Argon2-only policy."""
        return cls(password_hash=_build_default_password_hash())

    def __init__(self, password_hash: PasswordHash | None = None) -> None:
        """Initialize the helper with the provided pwdlib hash pipeline."""
        self.password_hash = password_hash or _build_default_password_hash()

    def hash(self, password: str) -> str:
        """Return a salted password hash."""
        return self.password_hash.hash(password)

    def verify(self, password: str, hashed: str) -> bool:
        """Verify a password against a stored hash.

        pwdlib delegates verification to the selected hasher, which performs
        constant-time comparison for password checks. Treat unsupported or
        malformed hashes, along with hasher-level validation failures, as
        authentication failures instead of bubbling an exception into the
        login flow.

        Returns:
            ``True`` when the password matches the stored hash, otherwise ``False``.
        """
        try:
            return self.password_hash.verify(password, hashed)
        except (UnknownHashError, ValueError):
            return False

    def verify_and_update(self, password: str, hashed: str) -> tuple[bool, str | None]:
        """Verify a password and return an updated hash when the stored one is deprecated.

        Uses pwdlib's ``verify_and_update``: when the configured pipeline marks the
        stored hash as deprecated, pwdlib returns the new hash so the caller can
        persist it. When the hash is already current, unsupported, malformed, or the
        password is wrong, the second element is ``None``.

        Returns:
            A pair (verified, new_hash). When ``verified`` is True and ``new_hash`` is not
            None, the caller should update the stored hash to ``new_hash``.
        """
        try:
            return self.password_hash.verify_and_update(password, hashed)
        except (UnknownHashError, ValueError):
            return (False, None)
