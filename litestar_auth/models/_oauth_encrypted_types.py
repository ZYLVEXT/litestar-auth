"""Shared OAuth token storage column types.

The mapped columns themselves are plain SQL string columns. Encryption and
decryption are applied explicitly via session-bound helpers in
``litestar_auth.oauth_encryption``.
"""

from __future__ import annotations

from sqlalchemy import String

oauth_access_token_type = String(length=2048)
oauth_refresh_token_type = String(length=2048)
