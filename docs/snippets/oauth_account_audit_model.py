"""Example: OAuth account model with audit columns (local copy; pick one mapped class per table).

``UUIDBase`` and ``UUIDAuditBase`` in Advanced Alchemy share metadata; you cannot
register two concrete subclasses with the same ``__tablename__`` in one process.
If your database already has ``created_at`` / ``updated_at`` on ``oauth_account``,
subclass ``UUIDAuditBase`` with :class:`~litestar_auth.models.OAuthAccountMixin`
instead of importing both the bundled ``OAuthAccount`` and an audit variant.
"""

from __future__ import annotations

from advanced_alchemy.base import UUIDAuditBase

from litestar_auth.models import OAuthAccountMixin


class OAuthAccountWithAudit(OAuthAccountMixin, UUIDAuditBase):
    """Example only — adapt names and ``User`` side to your app."""

    __tablename__ = "oauth_account"
