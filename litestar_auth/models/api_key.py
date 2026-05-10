"""API-key ORM model (import without loading :class:`~litestar_auth.models.user.User`)."""

from __future__ import annotations

from advanced_alchemy.base import UUIDBase

from litestar_auth.models.mixins import ApiKeyMixin


class ApiKey(ApiKeyMixin, UUIDBase):
    """API key linked to a local user.

    The non-secret ``key_id`` is globally unique and indexed so future authentication
    strategies can resolve candidate rows without scanning or comparing every stored
    digest. ``hashed_secret`` stores the keyed secret digest; the raw secret is never
    represented on the ORM model. ``encrypted_secret`` is reserved for signing-mode
    storage and remains nullable until that feature is enabled by a later task.
    """

    __tablename__ = "api_key"
