"""Shared OAuth token storage column types.

The mapped columns themselves are plain SQL string columns. Encryption and
decryption are applied explicitly via session-bound helpers in
``litestar_auth.oauth_encryption``.
"""

from __future__ import annotations

from sqlalchemy import String

# Stored values are Fernet-encrypted token blobs (not raw plaintext). Fernet adds fixed
# framing (version, timestamp, IV, HMAC) plus PKCS7-padded ciphertext, then URL-safe
# base64 expands the binary length by ~4/3. A ~1500-byte OAuth JWT can therefore exceed
# 2048 characters once encrypted; 4096 matches common provider maximums with margin.
_OAUTH_TOKEN_VARCHAR_LENGTH = 4096

oauth_access_token_type = String(length=_OAUTH_TOKEN_VARCHAR_LENGTH)
oauth_refresh_token_type = String(length=_OAUTH_TOKEN_VARCHAR_LENGTH)
