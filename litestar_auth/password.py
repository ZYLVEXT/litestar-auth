"""Password hashing helpers built on top of pwdlib."""

from __future__ import annotations

from pwdlib import PasswordHash
from pwdlib.exceptions import UnknownHashError
from pwdlib.hashers.argon2 import Argon2Hasher
from pwdlib.hashers.bcrypt import BcryptHasher


class PasswordHelper:
    """Hash and verify passwords with Argon2 and bcrypt support."""

    def __init__(self, password_hash: PasswordHash | None = None) -> None:
        """Initialize the helper with Argon2 as primary and bcrypt as fallback."""
        self.password_hash = password_hash or PasswordHash((Argon2Hasher(), BcryptHasher()))

    def hash(self, password: str) -> str:
        """Return a salted password hash."""
        return self.password_hash.hash(password)

    def verify(self, password: str, hashed: str) -> bool:
        """Verify a password against a stored hash.

        pwdlib delegates verification to the selected hasher, which performs
        constant-time comparison for password checks.

        Returns:
            ``True`` when the password matches the stored hash, otherwise ``False``.
        """
        try:
            return self.password_hash.verify(password, hashed)
        except UnknownHashError:
            return False

    def verify_and_update(self, password: str, hashed: str) -> tuple[bool, str | None]:
        """Verify a password and return an updated hash when the stored one is deprecated.

        Uses pwdlib's verify_and_update: when the stored hash is deprecated (e.g. bcrypt
        while Argon2 is preferred), pwdlib returns the new hash so the caller can persist it.
        When the hash is already current or the password is wrong, the second element is None.

        Returns:
            A pair (verified, new_hash). When ``verified`` is True and ``new_hash`` is not
            None, the caller should update the stored hash to ``new_hash``.
        """
        try:
            return self.password_hash.verify_and_update(password, hashed)
        except UnknownHashError:
            return (False, None)
