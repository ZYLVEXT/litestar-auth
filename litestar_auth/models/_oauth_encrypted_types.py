"""Shared EncryptedString column types for OAuth token fields (single cast for AA typing)."""

from __future__ import annotations

from collections.abc import Callable
from typing import cast

from advanced_alchemy.types import EncryptedString

from litestar_auth.oauth_encryption import (
    OAuthEncryptionKeyCallable,
    _RawFernetBackend,
    get_oauth_encryption_key_callable,
)

# Advanced Alchemy types ``EncryptedString.key`` as ``Callable[[], str | bytes]``; the
# registry-backed resolver can return ``None`` when no scope key is set (plaintext mode).
_oauth_key_loader: OAuthEncryptionKeyCallable = get_oauth_encryption_key_callable()
_oauth_token_key: Callable[[], str | bytes] = cast("Callable[[], str | bytes]", _oauth_key_loader)

oauth_access_token_type = EncryptedString(
    key=_oauth_token_key,
    backend=_RawFernetBackend,
    length=2048,
)
oauth_refresh_token_type = EncryptedString(
    key=_oauth_token_key,
    backend=_RawFernetBackend,
    length=2048,
)
