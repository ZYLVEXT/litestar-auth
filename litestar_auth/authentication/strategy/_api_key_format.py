"""API-key format parsing and verification helpers."""

from __future__ import annotations

import hashlib
import hmac
import re
from dataclasses import dataclass

MAX_API_KEY_LENGTH = 4096
MAX_API_KEY_SECRET_LENGTH = 1024
API_KEY_PREFIX = "ak"

_API_KEY_ENV_PATTERN = re.compile(r"[A-Za-z0-9][A-Za-z0-9-]{0,31}")
_API_KEY_ID_PATTERN = re.compile(r"[A-Za-z0-9][A-Za-z0-9_-]{0,127}")


@dataclass(frozen=True, slots=True)
class ParsedApiKey:
    """Validated API-key token fields."""

    prefix_env: str
    key_id: str
    secret: str


def parse_api_key(
    value: str,
    *,
    expected_prefix_env: str | None = None,
    prefix: str = API_KEY_PREFIX,
) -> ParsedApiKey | None:
    """Parse the canonical ``ak_<env>_<key_id>.<secret>`` API-key format.

    Returns:
        Parsed token fields, or ``None`` when the token is malformed or belongs
        to another configured environment marker.
    """
    if len(value) > MAX_API_KEY_LENGTH or not _has_valid_secret_segment(value):
        return None

    public_part, _, secret = value.partition(".")
    prefix_marker = f"{prefix}_"
    if not public_part.startswith(prefix_marker):
        return None
    env_and_key_id = public_part.removeprefix(prefix_marker)
    prefix_env, separator, key_id = env_and_key_id.partition("_")
    if not _has_valid_public_segments(prefix_env, separator, key_id, expected_prefix_env=expected_prefix_env):
        return None

    return ParsedApiKey(prefix_env=prefix_env, key_id=key_id, secret=secret)


def _has_valid_secret_segment(value: str) -> bool:
    """Return whether ``value`` contains one bounded non-empty secret segment."""
    _public_part, separator, secret = value.partition(".")
    return (
        separator == "."
        and bool(secret)
        and len(secret) <= MAX_API_KEY_SECRET_LENGTH
        and not any(char.isspace() for char in secret)
    )


def _has_valid_public_segments(
    prefix_env: str,
    separator: str,
    key_id: str,
    *,
    expected_prefix_env: str | None,
) -> bool:
    """Return whether public API-key lookup fields are well-formed."""
    return (
        separator == "_"
        and (expected_prefix_env is None or prefix_env == expected_prefix_env)
        and _API_KEY_ENV_PATTERN.fullmatch(prefix_env) is not None
        and _API_KEY_ID_PATTERN.fullmatch(key_id) is not None
    )


def digest_api_key_secret(*, api_key_hash_secret: bytes, secret: str) -> bytes:
    """Return the keyed HMAC-SHA-256 digest stored for an API-key secret."""
    return hmac.new(api_key_hash_secret, secret.encode(), hashlib.sha256).digest()


def api_key_secret_matches(*, stored_digest: bytes, api_key_hash_secret: bytes, secret: str) -> bool:
    """Return whether ``secret`` matches ``stored_digest`` using constant-time comparison."""
    candidate_digest = digest_api_key_secret(api_key_hash_secret=api_key_hash_secret, secret=secret)
    return hmac.compare_digest(stored_digest, candidate_digest)
